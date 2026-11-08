dataset = xdr_data
| filter host != null
| comp count() as count by host
| sort desc count
| limit 10
