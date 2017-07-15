pcap_test: main.o pcap.o
	gcc -o pcap_test main.o pcap.o -lpcap
main.o: main.c
	gcc -c -o main.o main.c
pcap.o: pcap.c
	gcc -c -o pcap.o pcap.c
clean:
	rm -rf *.o pcap_test
