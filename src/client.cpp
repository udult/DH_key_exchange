// client side
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <string>
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
	// client init
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1)
	{
		perror("socket");
		return 1;
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);
	addr.sin_addr.s_addr = inet_addr(IP);

	if (connect(sockfd, (struct sockaddr*) &addr, sizeof(addr)) == -1)
	{
		perror("connect");
		close(sockfd);
		return 1;
	}

	std::cout << "Client is connected on " << inet_ntoa(addr.sin_addr) << ':' << ntohs(addr.sin_port) << std::endl;

	// receive dh common
	char buffer[CAPACITY] = {'\0'};

	if (recv(sockfd, buffer, sizeof(buffer), 0) <= 0)
	{
		std::cout << "Failed to receive DH common" << std::endl;
		close(sockfd);
		return 1;
	}

	// unpack dh common
	std::string p_s, q_s, g_s;

	int count = 0;

	while (buffer[count] != '.' && buffer[count] != '\0')
		p_s.push_back(buffer[count++]);

	count++;

	while (buffer[count] != '.' && buffer[count] != '\0')
		q_s.push_back(buffer[count++]);

	count++;

	while (buffer[count] != '.' && buffer[count] != '\0')
		g_s.push_back(buffer[count++]);

	std::cout << "\nDH common parameters received:\n" << "p: " << p_s << '\n' << "q: " << q_s << '\n' << "g: " << g_s << std::endl;
	
	try
	{
		// init dh common
		DH dh;
		AutoSeededRandomPool prng;

		const Integer p(p_s.c_str());
		const Integer q(q_s.c_str());
		const Integer g(g_s.c_str());

		dh.AccessGroupParameters().Initialize(p, q, g);

		// validate dh common
		if (!dh.GetGroupParameters().ValidateGroup(prng, 3))
			throw std::runtime_error("dh: Failed to validate prime and generator");

		// gen dh key pair
		SecByteBlock pub(dh.PublicKeyLength());
		SecByteBlock priv(dh.PrivateKeyLength());

		dh.GenerateKeyPair(prng, priv, pub);

		std::string pub_s; 
		std::string priv_s;

		ArraySource(pub.data(), pub.size(), true,
			new HexEncoder(
				new StringSink(pub_s)
			)
		);

		ArraySource(priv.data(), priv.size(), true,
			new HexEncoder(
				new StringSink(priv_s)
			)
		);

		std::cout << "\nDH public key generated:\n" << pub_s << std::endl;
		std::cout << "\nDH private key generated:\n" << priv_s << std::endl;

		// send dh public key
		if (send(sockfd, pub.data(), pub.size(), 0) <= 0)
			throw std::runtime_error("Failed to send DH public key");

		// receive dh public key
		SecByteBlock pubRecv(dh.PublicKeyLength());

		if (recv(sockfd, pubRecv.data(), pubRecv.size(), 0) <= 0)
			throw std::runtime_error("Failed to receive DH public key");

		std::string pubRecv_s;

		ArraySource(pubRecv.data(), pubRecv.size(), true,
			new HexEncoder(
				new StringSink(pubRecv_s)
			)
		);

		std::cout << "\nDH public key received:\n" << pubRecv_s << std::endl;

		// calc secret key
		SecByteBlock secretKey(dh.AgreedValueLength());
		
		if (!dh.Agree(secretKey, priv, pubRecv))
			throw std::runtime_error("dh: Failed to calculate secret key");

		std::string secretKey_s;

		ArraySource(secretKey.data(), secretKey.size(), true,
			new HexEncoder(
				new StringSink(secretKey_s)
			)
		);

		std::cout << "\nDH secret key calculated:\n" << secretKey_s << std::endl;
	}

	catch (const Exception &exc)
	{
		std::cout << exc.what() << std::endl;
		close(sockfd);
		return 1;
	}

	close(sockfd);

	return 0;
}

/* _EOF_ */