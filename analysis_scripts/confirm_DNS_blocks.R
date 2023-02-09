censorious_DNS_servers <- c("203.109.71.154", "123.176.40.68", "106.51.113.17", "123.176.40.69", "49.207.46.38", "123.176.40.67", "49.207.46.62", "202.83.21.15", "49.205.75.6", "202.83.24.75", "202.83.21.14", "218.248.112.60")

for (server in censorious_DNS_servers) {
  query_with_parameters <- paste('{ "result.test_result.resolved_ip": "', server, '"}', sep = "")
  responses <- dnsprobe$find(query = query_with_parameters, fields='{"_id": 1}')
  
  for (response in responses$'_id') {
    query_with_parameters <- paste('{"_id": { "$oid" : "', response, '" } }', sep = "")
    updates <- dnsprobe$update(query = query_with_parameters, update = '{ "$set" : { "confirmed_block" : "True"} }')
  }
}


mongo$update(
  query = paste0('{"_id": { "$oid" : "', mongoID, '" } }'),
  update = '{ "$set" : { "confirmed_block" : "True"} }'
)


bad_measurements <- c('AS133997','AS132559','AS132976', 'AS133287',  'AS134177',  'AS134293', 'AS134674' , 'AS135690', 'AS136305',  'AS138277', 'AS139567', 'AS45235', 'AS58965', 'AS133720')
for (asn in bad_measurements) {
  query_with_parameters <- paste('{ "ip_info.asn.asn": "', asn, '"}', sep = "")
  responses <- tlsprobe$find(query = query_with_parameters, fields='{"_id": 1}')
  if (length(responses) == 0) {
    next
  }
  
  for (response in responses$'_id') {
    query_with_parameters <- paste('{"_id": { "$oid" : "', response, '" } }', sep = "")
    updates <- tlsprobe$update(query = query_with_parameters, update = '{ "$set" : { "invalid" : "True"} }')
  }
}
