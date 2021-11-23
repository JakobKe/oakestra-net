from requests.mongodb_requests import mongo_find_job_by_ip, mongo_find_job_by_name
from requests.root_service_manager_requests import cloud_table_query_ip, cloud_table_query_service_name


def service_resolution(service_name):
    """
    Resolves the service instance list by service name with the local DB,
    if no result found the query is propagated to the System Manager
    """
    # resolve it locally
    jobs = mongo_find_job_by_name(service_name)
    instances = None
    siplist = None

    # if no results, ask the root orc
    if jobs is None:
        query_result = cloud_table_query_service_name(service_name)
        instances = query_result['instance_list']
        siplist = query_result['service_ip_list']
    else:
        instances = jobs['instance_list']
        siplist = jobs['service_ip_list']

    return instances,siplist


def service_resolution_ip(ip_string):
    """
    Resolves the service instance list by service ServiceIP with the local DB,
    if no result found the query is propagated to the System Manager

    returns:
        name: string #service name
        instances: {
                        instance_number: int
                        namespace_ip: string
                        host_ip: string
                        host_port: string
                        service_ip: [
                            {
                                IpType: string
                                Address: string
                            }
                        ]
                    }
    """
    # resolve it locally
    job = mongo_find_job_by_ip(ip_string)

    # if no results, ask the root orc
    if job is None:
        job = cloud_table_query_ip(ip_string)
        if job is None:
            return "", []

    instances = job['instance_list']
    service_ip_list = job['service_ip_list']
    for elem in instances:
        elem['service_ip'] = service_ip_list
        elem['service_ip'].append({
            "IpType": "instance_ip",
            "Address": elem['instance_ip']
        })

    name = job.get('job_name')

    return name, instances
