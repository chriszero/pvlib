set(src	log.c
	rfcomm.c
	smabluetooth.c
	smadata2plus.c
	smanet.c
	connection.c
	pvlib.c
)
	
add_library(pvlib ${src})
target_link_libraries(pvlib bluetooth)
