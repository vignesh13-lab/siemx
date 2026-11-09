dataset = xdr_data
| filter agent_hostname != null
| comp count() as count by agent_hostname
| sort desc count
| limit 10
