CC = mips-openwrt-linux-gcc
OBJS = client_udp.o server_udp.o natHandler.o client_tcp.o server_tcp.o

udp:client_udp.o server_udp.o natHandler.o
	$(CC) server_udp.o natHandler.o -o server.udp -lpthread
	$(CC) client_udp.o -o client.udp -lpthread
	
tcp:client_tcp.o server_tcp.o natHandler.o
	$(CC) server_tcp.o natHandler.o -o server.tcp -lpthread
	$(CC) client_tcp.o -o client.tcp -lpthread

$(OBJS):%.o:%.c
	$(CC) -c $(CFLAGS) $< -o $@


clean:
	rm -f *.o *.tcp *.udp
