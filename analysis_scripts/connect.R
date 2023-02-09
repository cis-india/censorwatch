connection_string = 'mongodb://localhost:27017/?readPreference=primary&appname=MongoDB%20Compass&ssl=false'
dnsprobe = mongo(collection="dnsprobe", db="log_database", url=connection_string)
tlsprobe = mongo(collection="tlsprobe", db="log_database", url=connection_string)
httpprobe = mongo(collection="http2probe", db="log_database", url=connection_string)