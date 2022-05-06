# Configure k3s traefik ingress

Here is an example configuration for a k3s standard traefik ingress

```yaml
# tcp/udp ingress routes
apiVersion: traefik.containo.us/v1alpha1
kind: IngressRouteTCP
metadata:
  name: "uyuni-proxy-rule-ssh"
  namespace: "{{ .Values.namespace }}"
spec:
  entryPoints:
    - ssh
  routes:
    - match: HostSNI(`*`)
      services:
        - name: uyuni-proxy
          port: 8022
---
apiVersion: traefik.containo.us/v1alpha1
kind: IngressRouteUDP
metadata:
  name: "uyuni-proxy-rule-udp"
  namespace: "{{ .Values.namespace }}"
spec:
  entryPoints:
    - tftp
  routes:
    - match: HostSNI(`*`)
      services:
        - name: uyuni-proxy
          port: 69          
---
# Regular ingress routes
apiVersion: traefik.containo.us/v1alpha1
kind: IngressRoute
metadata:
  name: "uyuni-proxy-rule-salt-publish"
  namespace: "{{ .Values.namespace }}"
spec:
  entryPoints:
    - salt-publish
  routes:
    - match: Host(`{{ .Values.host }}`)
      kind: Rule
      services:
        - name: uyuni-proxy
          port: 4505
---
apiVersion: traefik.containo.us/v1alpha1
kind: IngressRoute
metadata:
  name: "uyuni-proxy-rule-salt-request"
  namespace: "{{ .Values.namespace }}"
spec:
  entryPoints:
    - salt-request
  routes:
    - match: Host(`{{ .Values.host }}`)
      kind: Rule
      services:
        - name: uyuni-proxy
          port: 4506
---
# Override the default config to include new entrypoints
apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: traefik
  namespace: kube-system
spec:
  valuesContent: |-
    entryPoints:
      salt-publish:
        address: ":4505"
      salt-request:
        address: ":4506"
      ssh:
        address: ":8022/tcp"
      tftp:
        address: ":69/udp"

```