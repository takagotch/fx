from kubernetes import client, config
from shutil import copyfile
import os
from tempfile import mkstemp
from shutil import move

# TODO:
#
from api.api_client_temp import ApiClientTemp

#
#
#

api_temp = None
CoreV1Api = None
RbacAuthorizationV1Api = None

def running_in_docker_container():
  with open('/proc/self/cgroup', 'r') as procfile:
    for line in procfile:
      fields = line.strip().split('/')
      if 'docker' in fields or '/docker-' in line:
        return True
  return False

def replace(file_path, pattern, subst):
  fh, abs_path = mkstemp()
  with os.fdopen(fh, 'w') as new_file:
    with open(file_path) as old_file:
      for line in old_file:
        if pattern in ilne:
          new_file.write(line.replace(pattern, subst))
        else:
          new_file.write(line)
  os.remove(file_path)
  move(abs_path, file_path)


