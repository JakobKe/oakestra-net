import os
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from datetime import datetime

MONGO_URL = os.environ.get('CLOUD_MONGO_URL')
MONGO_PORT = os.environ.get('CLOUD_MONGO_PORT')

MONGO_ADDR_JOBS = 'mongodb://' + str(MONGO_URL) + ':' + str(MONGO_PORT) + '/jobs'
MONGO_ADDR_NET = 'mongodb://' + str(MONGO_URL) + ':' + str(MONGO_PORT) + '/netcache'
MONGO_ADDR_CLUSTER = 'mongodb://' + str(MONGO_URL) + ':' + str(MONGO_PORT) + '/cluster'

mongo_jobs = None
mongo_clusters = None
mongo_net = None

app = None

CLUSTERS_FRESHNESS_INTERVAL = 45


def mongo_init(flask_app):
    global app
    global mongo_jobs, mongo_net, mongo_clusters

    app = flask_app

    app.logger.info("Connecting to mongo...")

    # app.config["MONGO_URI"] = MONGO_ADDR
    try:
        mongo_jobs = PyMongo(app, uri=MONGO_ADDR_JOBS)
        mongo_net = PyMongo(app, uri=MONGO_ADDR_NET)
        mongo_clusters = PyMongo(app, uri=MONGO_ADDR_CLUSTER)
    except Exception as e:
        app.logger.fatal(e)
    app.logger.info("MONGODB - init mongo")


# ......... JOB OPERATIONS .........................
####################################################

def mongo_insert_job(obj):
    global mongo_jobs
    app.logger.info("MONGODB - insert job...")
    deployment_descriptor = obj['deployment_descriptor']

    # jobname and details generation
    job_name = deployment_descriptor['app_name'] \
               + "." + deployment_descriptor['app_ns'] \
               + "." + deployment_descriptor['service_name'] \
               + "." + deployment_descriptor['service_ns']
    job_content = {
        'system_job_id': obj.get('system_job_id'),
        'job_name': job_name,
        'service_ip_list': obj.get('service_ip_list'),
        **deployment_descriptor  # The content of the input deployment descriptor
    }
    # job insertion
    new_job = mongo_jobs.db.jobs.find_one_and_update(
        {'job_name': job_name},
        {'$set': job_content},
        upsert=True,
        return_document=True
    )
    app.logger.info("MONGODB - job {} inserted".format(str(new_job.get('_id'))))
    return str(new_job.get('_id'))


def mongo_remove_job(system_job_id):
    global mongo_jobs
    return mongo_jobs.db.jobs.remove({"system_job_id": system_job_id})


def mongo_get_all_jobs():
    global mongo_jobs
    return mongo_jobs.db.jobs.find()


def mongo_get_job_status(job_id):
    global mongo_jobs
    return mongo_jobs.db.jobs.find_one({'_id': ObjectId(job_id)}, {'status': 1})['status'] + '\n'


def mongo_update_job_status(job_id, status):
    global mongo_jobs
    return mongo_jobs.db.jobs.update_one({'_id': ObjectId(job_id)}, {'$set': {'status': status}})


def mongo_update_job_net_status(job_id, instances):
    global mongo_jobs
    job = mongo_jobs.db.jobs.find_one({'_id': ObjectId(job_id)})
    instance_list = job['instance_list']
    for instance in instances:
        instance_num = instance['instance_number']
        elem = instance_list[instance_num]
        elem['namespace_ip'] = instance['namespace_ip']
        elem['host_ip'] = instance['host_ip']
        elem['host_port'] = instance['host_port']
        instance_list[instance_num] = elem
    return mongo_jobs.db.jobs.find_one_and_update({'_id': ObjectId(job_id)}, {'$set': {'instance_list': instance_list}})


def mongo_find_job_by_id(job_id):
    global mongo_jobs
    return mongo_jobs.db.jobs.find_one(ObjectId(job_id))


def mongo_find_job_by_systemid(sys_id):
    global mongo_jobs
    return mongo_jobs.db.jobs.find_one({"system_job_id": sys_id})


def mongo_find_job_by_name(job_name):
    global mongo_jobs
    return mongo_jobs.db.jobs.find_one({'job_name': job_name})


def mongo_find_job_by_ip(ip):
    global mongo_jobs
    # Search by Service Ip
    job = mongo_jobs.db.jobs.find_one({'service_ip_list.Address': ip})
    if job is None:
        # Search by instance ip
        job = mongo_jobs.db.jobs.find_one({'instance_list.instance_ip': ip})
    return job


def mongo_update_job_status_and_instances_by_system_job_id(system_job_id, instance_list):
    global mongo_jobs
    print('Updating Job Status and assigning a cluster for this job...')
    mongo_jobs.db.jobs.update_one({'system_job_id': system_job_id},
                                  {'$set': {'instance_list': instance_list}})


def mongo_update_clean_one_instance(system_job_id, instance):
    """
    returns the replicas left
    """
    global mongo_jobs
    job = mongo_find_job_by_systemid(system_job_id)
    instances = job.get("instance_list")
    for i in range(len(instances)):
        if instances[i]['instance_number'] is instance:
            instances.remove(i)
            mongo_update_job_status_and_instances_by_system_job_id(system_job_id, instances)
            return True
    return False


# ........... SERVICE MANAGER OPERATIONS  ............
######################################################

def mongo_get_service_address_from_cache():
    """
    Pop an available Service address, if any, from the free addresses cache
    @return: int[4] in the shape [172,30,x,y]
    """
    global mongo_net
    netdb = mongo_net.db.netcache

    entry = netdb.find_one({'type': 'free_service_ip'})

    if entry is not None:
        netdb.delete_one({"_id": entry["_id"]})
        return entry["ipv4"]
    else:
        return None


def mongo_free_service_address_to_cache(address):
    """
    Add back an address to the cache
    @param address: int[4] in the shape [172,30,x,y]
    """
    global mongo_net
    netcache = mongo_net.db.netcache

    assert len(address) == 4
    for n in address:
        assert 0 <= n < 254

    netcache.insert_one({
        'type': 'free_service_ip',
        'ipv4': address
    })


def mongo_get_next_service_ip():
    """
    Returns the next available ip address from the addressing space 172.30.x.y/16
    @return: int[4] in the shape [172,30,x,y,]
    """
    global mongo_net
    netcache = mongo_net.db.netcache

    next_addr = netcache.find_one({'type': 'next_service_ip'})

    if next_addr is not None:
        return next_addr["ipv4"]
    else:
        ip4arr = [172, 30, 0, 0]
        netcache = mongo_net.db.netcache
        id = netcache.insert_one({
            'type': 'next_service_ip',
            'ipv4': ip4arr
        })
        return ip4arr


def mongo_update_next_service_ip(address):
    """
    Update the value for the next service ip available
    @param address: int[4] in the form [172,30,x,y] monotonically increasing with respect to the previous address
    """
    global mongo_net
    netcache = mongo_net.db.netcache

    # sanity check for the address
    assert len(address) == 4
    for n in address:
        assert 0 <= n < 256
    assert address[0] == 172
    assert address[1] == 30

    netcache.update_one({'type': 'next_service_ip'}, {'$set': {'ipv4': address}})


def mongo_get_next_subnet_ip():
    """
    Returns the next available subnetwork ip address from the addressing space 172.16.y.z/12
    @return: int[4] in the shape [172,x,y,z]
    """
    global mongo_net
    netcache = mongo_net.db.netcache

    next_addr = netcache.find_one({'type': 'next_subnet_ip'})

    if next_addr is not None:
        return next_addr["ipv4"]
    else:
        ip4arr = [172, 18, 0, 0]
        netcache = mongo_net.db.netcache
        id = netcache.insert_one({
            'type': 'next_subnet_ip',
            'ipv4': ip4arr
        })
        return ip4arr


def mongo_update_next_subnet_ip(address):
    """
    Update the value for the next subnet ip available
    @param address: int[4] in the form [172,x,y,z] monotonically increasing with respect to the previous address
    """
    global mongo_net
    netcache = mongo_net.db.netcache

    # sanity check for the address
    assert len(address) == 4
    for n in address:
        assert 0 <= n < 256
    assert address[0] == 172
    assert 17 < address[1] < 30

    netcache.update_one({'type': 'next_subnet_ip'}, {'$set': {'ipv4': address}})


def mongo_get_subnet_address_from_cache():
    """
    Pop an available Subnet address, if any, from the free addresses cache
    @return: int[4] in the shape [172,x,y,z]
    """
    global mongo_net
    netcache = mongo_net.db.netcache

    entry = netcache.find_one({'type': 'free_subnet_ip'})

    if entry is not None:
        netcache.delete_one({"_id": entry["_id"]})
        return entry["ipv4"]
    else:
        return None


def mongo_free_subnet_address_to_cache(address):
    """
    Add back a subnetwork address to the cache
    @param address: int[4] in the shape [172,30,x,y]
    """
    global mongo_net
    netcache = mongo_net.db.netcache

    assert len(address) == 4
    for n in address:
        assert 0 <= n < 256

    netcache.insert_one({
        'type': 'free_subnet_ip',
        'ipv4': address
    })


# ......... CLUSTER OPERATIONS ....................#
####################################################

def mongo_cluster_add(cluster_port, cluster_address, status):
    global mongo_clusters

    job = mongo_clusters.db.cluster.find_one_and_update(
        {"cluster_port": cluster_port, "cluster_address": cluster_address},
        {'$set':
             {"cluster_port": cluster_port,
              "cluster_address": cluster_address,
              "status": status}
         }, return_document=True)

    mongo_clusters.db.cluster.find_one_and_update(
        {"_id": job.get('_id')},
        {'$set': {
            "cluster_id": str(job.get('_id'))
        }})


def mongo_set_cluster_status(cluster_id, cluster_status):
    global mongo_clusters

    job = mongo_clusters.db.cluster.find_one_and_update(
        {"cluster_id": cluster_id},
        {'$set':
             {"cluster_info.status": cluster_status}
         })


def mongo_cluster_remove(cluster_id):
    global mongo_clusters
    mongo_clusters.db.cluster.remove({"cluster_id": cluster_id})


def mongo_get_cluster_by_ip(cluster_ip):
    global mongo_clusters
    return mongo_clusters.db.cluster.find_one({"cluster_info.cluster_address": cluster_ip})


# .......... INTERESTS OPERATIONS .........#
###########################################

def mongo_get_cluster_interested_to_job(job_name):
    global mongo_clusters
    return mongo_clusters.db.cluster.find({"interests": job_name})


def mongo_register_cluster_job_interest(cluster_id, job_name):
    global mongo_clusters
    interests = mongo_clusters.db.cluster.find_one({"cluster_id": cluster_id}).get("interests")
    if interests is None:
        interests = []
    if job_name in interests:
        return
    interests.append(job_name)
    mongo_clusters.db.cluster.find_one_and_update(
        {"cluster_id": cluster_id},
        {'$set': {
            "interests": interests
        }}
    )


def mongo_remove_cluster_job_interest(cluster_id, job_name):
    global mongo_clusters
    interests = mongo_clusters.db.cluster.find_one({"cluster_id": cluster_id}).get("interests")
    interests.remove(job_name)
    mongo_clusters.db.cluster.find_one_and_update(
        {"cluster_id": cluster_id},
        {'$set': {
            "interests": interests
        }}
    )
