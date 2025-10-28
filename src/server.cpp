// server side
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <string>
#include <sstream>
#include <iostream>

#include <cryptopp/dh.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>

#define PORT 2001
#define IP "127.0.0.1"

#define CAPACITY 2048 

using namespace CryptoPP;

int main()
{
	/********** server init **********/
	int server = socket(AF_INET, SOCK_STREAM, 0);
	if (server == -1)
	{
		perror("socket");
		return 1;
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);
	addr.sin_addr.s_addr = inet_addr(IP);

	if (bind(server, (struct sockaddr*) &addr, sizeof(addr)) == -1)
	{
		perror("bind");
		close(server);
		return 1;
	}

	std::cout << "Server is running at " << inet_ntoa(addr.sin_addr) << ':' << ntohs(addr.sin_port) << std::endl;

	if (listen(server, 2) == -1)
	{
		perror("listen");
		close(server);
		return 1;
	}

	std::cout << "Waiting for connection..." << std::endl;

	/********** accept connection **********/
	int client1, client2;

	struct sockaddr_in clientaddr1, clientaddr2;

	socklen_t len1, len2;
	len1 = len2 = sizeof(sockaddr_in);

	client1 = accept(server, (struct sockaddr*) &clientaddr1, &len1);
	if (client1 == -1)
	{
		perror("accept");
		close(server);
		return 1;
	}

	std::cout << "Client 1 is connected from " << inet_ntoa(clientaddr1.sin_addr) << ':' << ntohs(clientaddr1.sin_port) << std::endl;

	client2 = accept(server, (struct sockaddr*) &clientaddr2, &len2);
	if (client2 == -1)
	{
		perror("accept");
		close(server);
		return 1;
	}

	std::cout << "Client 2 is connected from " << inet_ntoa(clientaddr2.sin_addr) << ':' << ntohs(clientaddr2.sin_port) << std::endl;

	/********** Diffie-Hellman key exchange **********/
	try
	{
		// gen dh common
		DH dh;
		AutoSeededRandomPool prng;
		dh.AccessGroupParameters().GenerateRandomWithKeySize(prng, CAPACITY);

		const Integer &p = dh.GetGroupParameters().GetModulus();
		const Integer &q = dh.GetGroupParameters().GetSubgroupOrder();
		const Integer &g = dh.GetGroupParameters().GetGenerator();

		std::cout << "\nDH common parameters:\n" << "p: " << p << '\n' << "q: " << q << '\n' << "g: " << g << std::endl;
		
		// send dh common
		std::stringstream ss;
		ss << p << q << g;

		std::string buffer = ss.str();

		if (send(client1, buffer.c_str(), buffer.size(), 0) <= 0)
			throw std::runtime_error("Failed to send DH common to client 1");

		if (send(client2, buffer.c_str(), buffer.size(), 0) <= 0)
			throw std::runtime_error("Failed to send DH common to client 2");

		// receive public dh keys from clients
		SecByteBlock publicKey1(dh.PublicKeyLength());
		SecByteBlock publicKey2(dh.PublicKeyLength());

		if (recv(client1, publicKey1.data(), publicKey1.size(), 0) <= 0)
			throw std::runtime_error("Failed to receive DH public key from client 1");

		if (recv(client2, publicKey2.data(), publicKey2.size(), 0) <= 0)
			throw std::runtime_error("Failed to receive DH public key from client 2");

		std::string pub1_s;
		std::string pub2_s;

		ArraySource(publicKey1.data(), publicKey1.size(), true,
			new HexEncoder(
				new StringSink(pub1_s)
			)
		);

		ArraySource(publicKey2.data(), publicKey2.size(), true,
			new HexEncoder(
				new StringSink(pub2_s)
			)
		);

		std::cout << "\nClient 1 DH public key:\n" << pub1_s << std::endl;
		std::cout << "\nClient 2 DH public key:\n" << pub2_s << std::endl;

		// resend public dh keys between clients
		if (send(client1, publicKey2.data(), publicKey2.size(), 0) <= 0)
			throw std::runtime_error("Failed to resend DH public key to client 1");

		if (send(client2, publicKey1.data(), publicKey1.size(), 0) <= 0)	
			throw std::runtime_error("Failed to resend DH public key to client 2");

		std::cout << "\nDH public keys has been exchanged" << std::endl;
	}

	catch (const Exception &exc)
	{
		std::cout << exc.what() << std::endl;
		close(server);
		return 1;
	}

	close(server);

	return 0;
}

/* _EOF_ */