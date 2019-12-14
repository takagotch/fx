from kubernates import client, config

class Role:
  def __init__(self, name, priority, rules=None, namespace=None, kind=None, time=None):
    self.name = name
    self.priority = priority
    self.rules = rules
    self.namespace = namespace
    self.kind = kind
    self.time = time

  def get_rules(self):
    config.load_kube_config()
    v1 = client.RbacAuthoriztionV1Api()
    if self.kind.lower() == "role":
      return (v1.read_namespaced_role(self.name, self.namespace)).rule
    else:
      return (v1.read_cluster_role(self.name)).rules

