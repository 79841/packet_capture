pcap_capture: pcap.c
	gcc -o pcap_capture pcap.c -lpcap
clean:
	rm -rf pcap_test
