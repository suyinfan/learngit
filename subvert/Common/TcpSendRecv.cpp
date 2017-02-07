#include "stdafx.h"
#include "TcpSendRecv.h"
#include <xutility>

CTcpSendRecv::CTcpSendRecv(SOCKET sock)
{
	this->m_sock = sock;
}

CTcpSendRecv::~CTcpSendRecv()
{
}


bool CTcpSendRecv::write(LPCVOID Buffer, SIZE_T nSize)
{
	//包头是SIZE_T
	//内容是Buffer
	int size = static_cast<int>(nSize);
	if (!this->raw_write(reinterpret_cast<unsigned char*>(&size), sizeof(int)))
	{
		return false;
	}

	unsigned char* data_buffer = new unsigned char[size];
	memcpy(data_buffer, Buffer, size);

	if (!this->raw_write(data_buffer, size))
	{
		delete[] data_buffer;
		return false;
	}

	delete[] data_buffer;
	return true;
}


bool CTcpSendRecv::read(LPVOID *lpBuffer, PSIZE_T lpInOutSize)
{
	//包头是SIZE_T
	//内容是Buffer
	//先读出来size
	//再构造buffer

	int data_length = 0;
	int data_length_size = this->raw_read(reinterpret_cast<unsigned char*>(&data_length), sizeof(int));

	if (!data_length_size || data_length_size != sizeof(int))
	{
		return false;
	}

	auto data_buffer = new char[data_length];

	for (int data_read = 0, offset = 0, data_to_read = data_length; data_to_read > 0; data_to_read -= data_read, offset += data_read)
	{
		data_read = this->raw_read(data_buffer + offset, data_to_read);

		if (!data_read || data_read == SOCKET_ERROR)
		{
			return false;
		}
	}
	*lpInOutSize = static_cast<SIZE_T>(data_length);
	*lpBuffer = reinterpret_cast<PVOID>(data_buffer);
	return true;
}


int CTcpSendRecv::raw_read(LPVOID lpBuffer, SIZE_T nSize)
{
	int bytes_read = 0;
	auto size = std::size_t(nSize);
	do
	{
		bytes_read = recv(this->m_sock, reinterpret_cast<char*>(lpBuffer), size, 0);
	} while (bytes_read == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK);

	if (bytes_read == 0 || bytes_read == SOCKET_ERROR)
	{
		return bytes_read;
	}
	else if (bytes_read < static_cast<int>(size))
	{
		int remaining_bytes_read = 0;

		do
		{
			remaining_bytes_read = recv(this->m_sock, reinterpret_cast<char*>(lpBuffer) + bytes_read, size - bytes_read, 0);
		} while (remaining_bytes_read == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK);

		if (remaining_bytes_read == 0 || remaining_bytes_read == SOCKET_ERROR)
		{
			return remaining_bytes_read;
		}

		bytes_read += remaining_bytes_read;
	}

	return bytes_read;
}


bool CTcpSendRecv::raw_write(LPCVOID Buffer, SIZE_T nSize)
{
	auto size = std::size_t(nSize);
	for (int data_sent = 0, offset = 0, data_to_send = size; data_to_send > 0; data_to_send -= data_sent, offset += data_sent)
	{
		data_sent = send(this->m_sock, reinterpret_cast<const char*>(Buffer) + offset, data_to_send, 0);

		if (data_sent == 0 || data_sent == SOCKET_ERROR)
		{
			return false;
		}
	}

	return true;
}


bool CTcpSendRecv::just_read(LPVOID lpBuffer, PSIZE_T lpSize)
{
	auto need_recv_size = *lpSize;
	int nsize = static_cast<int>(need_recv_size);
	auto bytes_read = recv(this->m_sock, reinterpret_cast<char*>(lpBuffer), nsize, 0);
	if (bytes_read == 0 || bytes_read == SOCKET_ERROR)
	{
		if (bytes_read == SOCKET_ERROR)
		{
			*lpSize = 0;
			return false;
		}
		return false;
	}
	*lpSize = static_cast<SIZE_T>(bytes_read);
	return true;
}


bool CTcpSendRecv::just_write(LPCVOID Buffer, SIZE_T nSize)
{
	return raw_write(Buffer,nSize);
}
