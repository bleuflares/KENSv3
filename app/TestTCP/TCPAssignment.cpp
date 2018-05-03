/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/E_TimeUtil.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_RoutingInfo.hpp>
#include "TCPAssignment.hpp"
#include <array>

namespace E
{

uint16_t implicit_bind_port = 49152 - 1;
uint32_t initial_seq_num = 0x00c0ffee;

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		this->syscall_connect(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		this->syscall_accept(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t)param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		this->syscall_getpeername(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet *packet)
{
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_num;
	uint32_t ack_num;
	uint8_t head_len;
	uint8_t flags;
	uint16_t rwnd;
	uint16_t urg_ptr;

	uint32_t src_ip, dst_ip;
	uint8_t tcp_seg[20];
	packet->readData(14 + 12, &src_ip, sizeof(src_ip));
	packet->readData(14 + 16, &dst_ip, sizeof(dst_ip));
	packet->readData(14 + 20, tcp_seg, sizeof(tcp_seg));

	if(NetworkUtil::tcp_sum(src_ip, dst_ip, tcp_seg, sizeof(tcp_seg)) != 0xFFFF)
	{
		this->freePacket(packet);
		return;
	}

	packet->readData(14 + 20 + 0, &src_port, sizeof(src_port));
	packet->readData(14 + 20 + 2, &dst_port, sizeof(dst_port));
	packet->readData(14 + 20 + 4, &seq_num, sizeof(seq_num));
	packet->readData(14 + 20 + 8, &ack_num, sizeof(ack_num));
	packet->readData(14 + 20 + 12, &head_len, sizeof(head_len));
	packet->readData(14 + 20 + 13, &flags, sizeof(flags));
	packet->readData(14 + 20 + 14, &rwnd, sizeof(rwnd));
	packet->readData(14 + 20 + 18, &urg_ptr, sizeof(urg_ptr));
	seq_num = ntohl(seq_num);
	ack_num = ntohl(ack_num);
	rwnd = ntohs(rwnd);
	urg_ptr = ntohs(urg_ptr);

	int l_fd;
	int s_fd;
	struct sock_info *l_socket;
	struct sock_info *s_socket;
	bool l_found = false;
	bool s_found = false;

	struct sockaddr_in src_addr;
	struct sockaddr_in dst_addr;
	src_addr.sin_family = AF_INET;
	src_addr.sin_addr.s_addr = src_ip;
	src_addr.sin_port = src_port;
	dst_addr.sin_family = AF_INET;
	dst_addr.sin_addr.s_addr = dst_ip;
	dst_addr.sin_port = dst_port;

	for(auto socket_iter = fd_to_socket.begin(); socket_iter != fd_to_socket.end(); ++socket_iter)
	{
		int fd = socket_iter->first[0];
		struct sock_info *socket = &socket_iter->second;

		if((((sockaddr_in *)&socket->src_addr)->sin_addr.s_addr == dst_ip || ((sockaddr_in *)&socket->src_addr)->sin_addr.s_addr == htonl(INADDR_ANY)) && ((sockaddr_in *)&socket->src_addr)->sin_port == dst_port)
		{
			if(socket->tcp_state == TCP_LISTEN)
			{
				l_fd = fd;
				l_socket = socket;
				l_found = true;
			}
			else
			{
				if(((sockaddr_in *)&socket->dst_addr)->sin_addr.s_addr == src_ip && ((sockaddr_in *)&socket->dst_addr)->sin_port == src_port)
				{
					s_fd = fd;
					s_socket = socket;
					s_found = true;
				}
			}
		}
	}

	int rcv_fd;
	struct sock_info *rcv_socket;

	if(s_found)
	{
		rcv_fd = s_fd;
		rcv_socket = s_socket;
	}
	else if(l_found)
	{
		rcv_fd = l_fd;
		rcv_socket = l_socket;
	}
	else
	{
		this->freePacket(packet);
		return;
	}

	Packet *reply_pkt;
	uint32_t packet_seq_num;
	uint32_t packet_ack_num;
	uint8_t packet_flags;
	uint16_t packet_checksum;
	uint32_t source, dest;

	switch(rcv_socket->tcp_state)
	{
		case TCP_LISTEN:
			if(flags == SYN)
			{
				int connection_count = 0;
				for(auto connection_iter = rcv_socket->connections.begin(); connection_iter != rcv_socket->connections.end(); ++connection_iter)
				{
					struct connection *connection_temp = &*connection_iter;
					if(connection_temp->connection_state == UNCONNECTED)
						connection_count++;
				}

				if(rcv_socket->backlog <= connection_count)
					break;

				struct connection connection;
				connection.src_addr = *(sockaddr *)&dst_addr;
				connection.dst_addr = *(sockaddr *)&src_addr;
				connection.connection_state = UNCONNECTED;
				connection.tcp_state = TCP_SYN_RCVD;
				connection.seq_num = initial_seq_num++;
				connection.ack_num = seq_num + 1;
				rcv_socket->connections.push_back(connection);

				packet_seq_num = htonl(connection.seq_num);
				packet_ack_num = htonl(connection.ack_num);
				packet_flags = (uint8_t) SYNACK;
				packet_checksum = (uint16_t) 0x0000;

				reply_pkt = this->clonePacket(packet);
				reply_pkt->writeData(14 + 12, &dst_ip, 4);
				reply_pkt->writeData(14 + 16, &src_ip, 4);
				reply_pkt->writeData(14 + 20 + 0, &dst_port, 2);
				reply_pkt->writeData(14 + 20 + 2, &src_port, 2);
				reply_pkt->writeData(14 + 20 + 4, &packet_seq_num, 4);
				reply_pkt->writeData(14 + 20 + 8, &packet_ack_num, 4);
				reply_pkt->writeData(14 + 20 + 13, &packet_flags, 1);
				reply_pkt->writeData(14 + 20 + 16, &packet_checksum, 2);

				reply_pkt->readData(14 + 12, &source, sizeof(source));
				reply_pkt->readData(14 + 16, &dest, sizeof(dest));
				reply_pkt->readData(14 + 20, tcp_seg, sizeof(tcp_seg));

				packet_checksum = htons(0xFFFF - NetworkUtil::tcp_sum(source, dest, tcp_seg, sizeof(tcp_seg)));
				reply_pkt->writeData(14 + 20 + 16, &packet_checksum, 2);

				this->sendPacket("IPv4", reply_pkt);
			}
			else if(flags == ACK)
			{
				struct connection *connection;
				auto connection_iter = rcv_socket->connections.begin();
				bool found = false;
				for(; connection_iter != rcv_socket->connections.end(); ++connection_iter)
				{
					connection = &*connection_iter;
					if(((sockaddr_in *)&connection->dst_addr)->sin_addr.s_addr == src_ip && ((sockaddr_in *)&connection->dst_addr)->sin_port == src_port)
					{
						found = true;
						break;
					}
				}
				if(!found)
					break;

				if(connection->seq_num + 1 == ack_num)
				{
					if(connection->tcp_state == TCP_SYN_RCVD)
					{
						connection->connection_state = CONNECTED;
						connection->tcp_state = TCP_ESTABLISHED;

						if(rcv_socket->accept_called)
						{
							int fd = this->createFileDescriptor(rcv_socket->pid);
							if(fd == -1)
							{
								this->returnSystemCall(rcv_socket->uuid, -1);
								return;
							}

							std::array<int, 2> fd_to_pid = {fd, rcv_socket->pid};

							if(fd_to_socket.find(fd_to_pid) != fd_to_socket.end())
							{
								this->returnSystemCall(rcv_socket->uuid, -1);
								return;
							}

							struct sock_info s_socket;
							s_socket.uuid = 0;
							s_socket.pid = rcv_socket->pid;
							s_socket.src_addr = connection->src_addr;
							s_socket.dst_addr = connection->dst_addr;
							s_socket.bound_state = BOUND;
							s_socket.connection_state = connection->connection_state;
							s_socket.tcp_state = connection->tcp_state;
							s_socket.backlog = 0;
							s_socket.seq_num = connection->seq_num;
							s_socket.ack_num = connection->ack_num;
							s_socket.accept_called = false;
							s_socket.accept_addr = NULL;
							s_socket.accept_addrlen = NULL;

							rcv_socket->connections.erase(connection_iter);
							fd_to_socket.insert(std::pair<std::array<int, 2>, sock_info>(fd_to_pid, s_socket));

							*rcv_socket->accept_addr = s_socket.dst_addr;
							*rcv_socket->accept_addrlen = sizeof(*rcv_socket->accept_addr);
							rcv_socket->accept_called = false;
							rcv_socket->accept_addr = NULL;
							rcv_socket->accept_addrlen = NULL;

							this->returnSystemCall(rcv_socket->uuid, fd);
						}
					}
					else if(connection->tcp_state == TCP_LAST_ACK)
					{
						connection->seq_num = ack_num;
						rcv_socket->connections.erase(connection_iter);
						if(rcv_socket->connections.empty())
						{
							UUID temp_uuid = rcv_socket->uuid;
							int temp_pid = rcv_socket->pid;
							std::array<int, 2> fd_to_pid = {rcv_fd, temp_pid};
							rcv_socket->connections.clear();
							fd_to_socket.erase(fd_to_pid);
							this->removeFileDescriptor(temp_pid, rcv_fd);

							this->returnSystemCall(temp_uuid, 0);
						}

					}
					else if(connection->tcp_state == TCP_FIN_WAIT_1)
						connection->tcp_state = TCP_FIN_WAIT_2;
					else if(connection->tcp_state == TCP_CLOSING)
					{
						connection->tcp_state = TCP_TIME_WAIT;

						struct timer_payload *timer = new struct timer_payload;
						timer->type = CONNECTION;
						timer->socket = rcv_socket;
						timer->connection = connection;

						timer->uuid = addTimer(timer, TimeUtil::makeTime(60, TimeUtil::SEC));
					}
				}
			}
			else if(flags == FIN)
			{
				struct connection *connection;
				bool found = false;
				for(auto connection_iter = rcv_socket->connections.begin(); connection_iter != rcv_socket->connections.end(); ++connection_iter)
				{
					connection = &*connection_iter;
					if(((sockaddr_in *)&connection->dst_addr)->sin_addr.s_addr == src_ip && ((sockaddr_in *)&connection->dst_addr)->sin_port == src_port)
					{
						found = true;
						break;
					}
				}
				if(!found)
					break;

				if(connection->tcp_state == TCP_ESTABLISHED)
				{
					connection->ack_num = seq_num + 1;

					packet_seq_num = htonl(connection->seq_num + 1);
					packet_ack_num = htonl(connection->ack_num);
					packet_flags = (uint8_t) ACK;
					packet_checksum = (uint16_t) 0x0000;

					reply_pkt = this->clonePacket(packet);
					reply_pkt->writeData(14 + 12, &dst_ip, 4);
					reply_pkt->writeData(14 + 16, &src_ip, 4);
					reply_pkt->writeData(14 + 20 + 0, &dst_port, 2);
					reply_pkt->writeData(14 + 20 + 2, &src_port, 2);
					reply_pkt->writeData(14 + 20 + 4, &packet_seq_num, 4);
					reply_pkt->writeData(14 + 20 + 8, &packet_ack_num, 4);
					reply_pkt->writeData(14 + 20 + 13, &packet_flags, 1);
					reply_pkt->writeData(14 + 20 + 16, &packet_checksum, 2);

					reply_pkt->readData(14 + 12, &source, sizeof(source));
					reply_pkt->readData(14 + 16, &dest, sizeof(dest));
					reply_pkt->readData(14 + 20, tcp_seg, sizeof(tcp_seg));

					packet_checksum = htons(0xFFFF - NetworkUtil::tcp_sum(source, dest, tcp_seg, sizeof(tcp_seg)));
					reply_pkt->writeData(14 + 20 + 16, &packet_checksum, 2);

					this->sendPacket("IPv4", reply_pkt);

					connection->tcp_state = TCP_CLOSE_WAIT;
				}
				else if(connection->tcp_state == TCP_FIN_WAIT_1)
				{
					connection->ack_num = seq_num + 1;

					packet_seq_num = htonl(connection->seq_num + 1);
					packet_ack_num = htonl(connection->ack_num);
					packet_flags = (uint8_t) ACK;
					packet_checksum = (uint16_t) 0x0000;

					reply_pkt = this->clonePacket(packet);
					reply_pkt->writeData(14 + 12, &dst_ip, 4);
					reply_pkt->writeData(14 + 16, &src_ip, 4);
					reply_pkt->writeData(14 + 20 + 0, &dst_port, 2);
					reply_pkt->writeData(14 + 20 + 2, &src_port, 2);
					reply_pkt->writeData(14 + 20 + 4, &packet_seq_num, 4);
					reply_pkt->writeData(14 + 20 + 8, &packet_ack_num, 4);
					reply_pkt->writeData(14 + 20 + 13, &packet_flags, 1);
					reply_pkt->writeData(14 + 20 + 16, &packet_checksum, 2);

					reply_pkt->readData(14 + 12, &source, sizeof(source));
					reply_pkt->readData(14 + 16, &dest, sizeof(dest));
					reply_pkt->readData(14 + 20, tcp_seg, sizeof(tcp_seg));

					packet_checksum = htons(0xFFFF - NetworkUtil::tcp_sum(source, dest, tcp_seg, sizeof(tcp_seg)));
					reply_pkt->writeData(14 + 20 + 16, &packet_checksum, 2);

					this->sendPacket("IPv4", reply_pkt);

					connection->tcp_state = TCP_CLOSING;
				}
				else if(connection->tcp_state == TCP_FIN_WAIT_2)
				{
					connection->ack_num = seq_num + 1;

					packet_seq_num = htonl(connection->seq_num + 1);
					packet_ack_num = htonl(connection->ack_num);
					packet_flags = (uint8_t) ACK;
					packet_checksum = (uint16_t) 0x0000;

					reply_pkt = this->clonePacket(packet);
					reply_pkt->writeData(14 + 12, &dst_ip, 4);
					reply_pkt->writeData(14 + 16, &src_ip, 4);
					reply_pkt->writeData(14 + 20 + 0, &dst_port, 2);
					reply_pkt->writeData(14 + 20 + 2, &src_port, 2);
					reply_pkt->writeData(14 + 20 + 4, &packet_seq_num, 4);
					reply_pkt->writeData(14 + 20 + 8, &packet_ack_num, 4);
					reply_pkt->writeData(14 + 20 + 13, &packet_flags, 1);
					reply_pkt->writeData(14 + 20 + 16, &packet_checksum, 2);

					reply_pkt->readData(14 + 12, &source, sizeof(source));
					reply_pkt->readData(14 + 16, &dest, sizeof(dest));
					reply_pkt->readData(14 + 20, tcp_seg, sizeof(tcp_seg));
						
					packet_checksum = htons(0xFFFF - NetworkUtil::tcp_sum(source, dest, tcp_seg, sizeof(tcp_seg)));
					reply_pkt->writeData(14 + 20 + 16, &packet_checksum, 2);

					this->sendPacket("IPv4", reply_pkt);

					connection->tcp_state = TCP_TIME_WAIT;
						
					struct timer_payload *timer = new struct timer_payload;
					timer->type = CONNECTION;
					timer->socket = rcv_socket;
					timer->connection = connection;

					timer->uuid = addTimer(timer, TimeUtil::makeTime(60, TimeUtil::SEC));
				}
			}
			break;

		case TCP_SYN_SENT:
			if(flags == SYNACK)
			{
				if(rcv_socket->seq_num + 1 == ack_num)
				{
					rcv_socket->ack_num = seq_num + 1;

					packet_seq_num = htonl(rcv_socket->seq_num + 1);
					packet_ack_num = htonl(rcv_socket->ack_num);
					packet_flags = (uint8_t) ACK;
					packet_checksum = (uint16_t) 0x0000;

					reply_pkt = this->clonePacket(packet);
					reply_pkt->writeData(14 + 12, &dst_ip, 4);
					reply_pkt->writeData(14 + 16, &src_ip, 4);
					reply_pkt->writeData(14 + 20 + 0, &dst_port, 2);
					reply_pkt->writeData(14 + 20 + 2, &src_port, 2);
					reply_pkt->writeData(14 + 20 + 4, &packet_seq_num, 4);
					reply_pkt->writeData(14 + 20 + 8, &packet_ack_num, 4);
					reply_pkt->writeData(14 + 20 + 13, &packet_flags, 1);
					reply_pkt->writeData(14 + 20 + 16, &packet_checksum, 2);

					reply_pkt->readData(14 + 12, &source, sizeof(source));
					reply_pkt->readData(14 + 16, &dest, sizeof(dest));
					reply_pkt->readData(14 + 20, tcp_seg, sizeof(tcp_seg));

					packet_checksum = htons(0xFFFF - NetworkUtil::tcp_sum(source, dest, tcp_seg, sizeof(tcp_seg)));
					reply_pkt->writeData(14 + 20 + 16, &packet_checksum, 2);

					this->sendPacket("IPv4", reply_pkt);

					rcv_socket->connection_state = CONNECTED;
					rcv_socket->tcp_state = TCP_ESTABLISHED;

					this->returnSystemCall(rcv_socket->uuid, 0);
				}
			}
			break;

		case TCP_ESTABLISHED:
			if(flags == FIN)
			{
				rcv_socket->ack_num = seq_num + 1;

				packet_seq_num = htonl(rcv_socket->seq_num + 1);
				packet_ack_num = htonl(rcv_socket->ack_num);
				packet_flags = (uint8_t) ACK;
				packet_checksum = (uint16_t) 0x0000;

				reply_pkt = this->clonePacket(packet);
				reply_pkt->writeData(14 + 12, &dst_ip, 4);
				reply_pkt->writeData(14 + 16, &src_ip, 4);
				reply_pkt->writeData(14 + 20 + 0, &dst_port, 2);
				reply_pkt->writeData(14 + 20 + 2, &src_port, 2);
				reply_pkt->writeData(14 + 20 + 4, &packet_seq_num, 4);
				reply_pkt->writeData(14 + 20 + 8, &packet_ack_num, 4);
				reply_pkt->writeData(14 + 20 + 13, &packet_flags, 1);
				reply_pkt->writeData(14 + 20 + 16, &packet_checksum, 2);

				reply_pkt->readData(14 + 12, &source, sizeof(source));
				reply_pkt->readData(14 + 16, &dest, sizeof(dest));
				reply_pkt->readData(14 + 20, tcp_seg, sizeof(tcp_seg));
				
				packet_checksum = htons(0xFFFF - NetworkUtil::tcp_sum(source, dest, tcp_seg, sizeof(tcp_seg)));
				reply_pkt->writeData(14 + 20 + 16, &packet_checksum, 2);

				this->sendPacket("IPv4", reply_pkt);

				rcv_socket->tcp_state = TCP_CLOSE_WAIT;
			}
			break;

		case TCP_LAST_ACK:
			if(flags == ACK)
			{
				int temp_pid = rcv_socket->pid;

				rcv_socket->seq_num = ack_num;
				rcv_socket->connections.clear();
				std::array<int, 2> fd_to_pid = {rcv_fd, rcv_socket->pid};
				fd_to_socket.erase(fd_to_pid);
				this->removeFileDescriptor(temp_pid, rcv_fd);
			}
			break;

		case TCP_FIN_WAIT_1:
			if(flags == ACK)
			{
				if(rcv_socket->seq_num + 1 == ack_num)
					rcv_socket->tcp_state = TCP_FIN_WAIT_2;
			}
			else if(flags == FIN)
			{
				rcv_socket->ack_num = seq_num + 1;

				packet_seq_num = htonl(rcv_socket->seq_num + 1);
				packet_ack_num = htonl(rcv_socket->ack_num);
				packet_flags = (uint8_t) ACK;
				packet_checksum = (uint16_t) 0x0000;

				reply_pkt = this->clonePacket(packet);
				reply_pkt->writeData(14 + 12, &dst_ip, 4);
				reply_pkt->writeData(14 + 16, &src_ip, 4);
				reply_pkt->writeData(14 + 20 + 0, &dst_port, 2);
				reply_pkt->writeData(14 + 20 + 2, &src_port, 2);
				reply_pkt->writeData(14 + 20 + 4, &packet_seq_num, 4);
				reply_pkt->writeData(14 + 20 + 8, &packet_ack_num, 4);
				reply_pkt->writeData(14 + 20 + 13, &packet_flags, 1);
				reply_pkt->writeData(14 + 20 + 16, &packet_checksum, 2);

				reply_pkt->readData(14 + 12, &source, sizeof(source));
				reply_pkt->readData(14 + 16, &dest, sizeof(dest));
				reply_pkt->readData(14 + 20, tcp_seg, sizeof(tcp_seg));
				
				packet_checksum = htons(0xFFFF - NetworkUtil::tcp_sum(source, dest, tcp_seg, sizeof(tcp_seg)));
				reply_pkt->writeData(14 + 20 + 16, &packet_checksum, 2);

				this->sendPacket("IPv4", reply_pkt);

				rcv_socket->tcp_state = TCP_CLOSING;
			}
			break;

		case TCP_FIN_WAIT_2:
			if(flags == FIN)
			{
				rcv_socket->ack_num = seq_num + 1;

				packet_seq_num = htonl(rcv_socket->seq_num + 1);
				packet_ack_num = htonl(rcv_socket->ack_num);
				packet_flags = (uint8_t) ACK;
				packet_checksum = (uint16_t) 0x0000;

				reply_pkt = this->clonePacket(packet);
				reply_pkt->writeData(14 + 12, &dst_ip, 4);
				reply_pkt->writeData(14 + 16, &src_ip, 4);
				reply_pkt->writeData(14 + 20 + 0, &dst_port, 2);
				reply_pkt->writeData(14 + 20 + 2, &src_port, 2);
				reply_pkt->writeData(14 + 20 + 4, &packet_seq_num, 4);
				reply_pkt->writeData(14 + 20 + 8, &packet_ack_num, 4);
				reply_pkt->writeData(14 + 20 + 13, &packet_flags, 1);
				reply_pkt->writeData(14 + 20 + 16, &packet_checksum, 2);

				reply_pkt->readData(14 + 12, &source, sizeof(source));
				reply_pkt->readData(14 + 16, &dest, sizeof(dest));
				reply_pkt->readData(14 + 20, tcp_seg, sizeof(tcp_seg));
				
				packet_checksum = htons(0xFFFF - NetworkUtil::tcp_sum(source, dest, tcp_seg, sizeof(tcp_seg)));
				reply_pkt->writeData(14 + 20 + 16, &packet_checksum, 2);

				this->sendPacket("IPv4", reply_pkt);

				rcv_socket->tcp_state = TCP_TIME_WAIT;

				struct timer_payload *timer = new struct timer_payload;
				timer->type = SOCKET;
				timer->socket = rcv_socket;

				timer->uuid = addTimer(timer, TimeUtil::makeTime(60, TimeUtil::SEC));
			}
			break; 

		case TCP_CLOSING:
			if(flags == ACK)
			{
				if(rcv_socket->seq_num + 1 == ack_num)
				{
					rcv_socket->tcp_state = TCP_TIME_WAIT;

					struct timer_payload *timer = new struct timer_payload;
					timer->type = SOCKET;
					timer->socket = rcv_socket;

					timer->uuid = addTimer(timer, TimeUtil::makeTime(60, TimeUtil::SEC));
				}
			}
			break;

		default:
			break;
	}

	this->freePacket(packet);
}

void TCPAssignment::timerCallback(void *payload)
{
	struct timer_payload *timer = (struct timer_payload *)payload;

	cancelTimer(timer->uuid);

	if(timer->type == SOCKET)
	{
		struct sock_info *socket = timer->socket;
		int fd;

		bool found = false;
		for(auto socket_iter = fd_to_socket.begin(); socket_iter != fd_to_socket.end(); ++socket_iter)
		{
			if(&socket_iter->second == socket)
			{
				fd = socket_iter->first[0];
				found = true;
				break;
			}
		}
		if(!found)
			assert(0);

		socket->connections.clear();
		std::array<int, 2> fd_to_pid = {fd, socket->pid};
		fd_to_socket.erase(fd_to_pid);
		this->removeFileDescriptor(socket->pid, fd);

		this->returnSystemCall(socket->uuid, 0);
	}
	else if(timer->type == CONNECTION)
	{
		struct sock_info *socket = timer->socket;
		struct connection *connection = timer->connection;
		auto connection_iter = socket->connections.begin();

		bool found = false;
		for(; connection_iter != socket->connections.end(); ++connection_iter)
		{
			if(&*connection_iter == connection)
			{
				found = true;
				break;
			}
		}
		if(!found)
			assert(0);

		socket->connections.erase(connection_iter);

		if(socket->connections.empty())
		{
			int fd;

			bool found = false;
			for(auto socket_iter = fd_to_socket.begin(); socket_iter != fd_to_socket.end(); ++socket_iter)
			{
				if(socket == &socket_iter->second)
				{
					fd = socket_iter->first[0];
					found = true;
					break;
				}
			}
			if(!found)
				assert(0);

			socket->connections.clear();
			std::array<int, 2> fd_to_pid = {fd, socket->pid};
			fd_to_socket.erase(fd_to_pid);
			this->removeFileDescriptor(socket->pid, fd);

			this->returnSystemCall(socket->uuid, 0);
		}
	}

	delete(timer);
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type__unused)
{
	int fd = this->createFileDescriptor(pid);
	if(fd == -1)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	std::array<int, 2> fd_to_pid = {fd, pid};
	
	struct sock_info socket;
	static struct sockaddr empty_addr;
	socket.uuid = 0;
	socket.pid = pid;
	socket.src_addr = empty_addr;
	socket.dst_addr = empty_addr;
	socket.bound_state = UNBOUND;
	socket.connection_state = UNCONNECTED;
	socket.tcp_state = TCP_CLOSED;
	socket.backlog = 0;
	socket.seq_num = initial_seq_num++;
	socket.ack_num = 0x00000000;
	socket.accept_called = false;
	socket.accept_addr = NULL;
	socket.accept_addrlen = NULL;

	fd_to_socket.insert(std::pair<std::array<int, 2>, sock_info>(fd_to_pid, socket));

	this->returnSystemCall(syscallUUID, fd);
	return;
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd)
{
	std::array<int , 2> fd_to_pid = {fd, pid};
	auto socket_iter = fd_to_socket.find(fd_to_pid);
	if(socket_iter == fd_to_socket.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	struct sock_info *socket = &socket_iter->second;
	
	Packet *fin_pkt;
	uint32_t packet_seq_num;
	uint32_t packet_ack_num;
	uint8_t packet_headerlen;
	uint8_t packet_flags;
	uint16_t packet_rwnd;
	uint16_t packet_checksum;
	uint16_t packet_pointer;
	uint32_t source, dest;
	uint8_t tcp_seg[20];

	switch(socket->tcp_state)
	{
		case TCP_LISTEN:
			if(socket->connections.empty())
			{
				socket->connections.clear();
				fd_to_socket.erase(fd_to_pid);
				this->removeFileDescriptor(pid, fd);

				this->returnSystemCall(syscallUUID, 0);
			}
			else
			{
				struct connection *connection;
				for(auto connection_iter = socket->connections.begin(); connection_iter != socket->connections.end(); ++connection_iter)
				{
					connection = &*connection_iter;

					if(connection->tcp_state == TCP_SYN_RCVD || connection->tcp_state == TCP_ESTABLISHED)
					{
						connection->seq_num += 1;

						packet_seq_num = htonl(connection->seq_num);
						packet_ack_num = htonl(0x00000000);
						packet_headerlen = (uint8_t) 0x50;
						packet_flags = (uint8_t) FIN;
						packet_rwnd = (uint16_t) htons(51200);
						packet_checksum = (uint16_t) 0x0000;
						packet_pointer = (uint16_t) 0x0000;

						fin_pkt = this->allocatePacket(14 + 20 + 20);
						fin_pkt->writeData(14 + 12, &((struct sockaddr_in *)&connection->src_addr)->sin_addr.s_addr, 4);
						fin_pkt->writeData(14 + 16, &((struct sockaddr_in *)&connection->dst_addr)->sin_addr.s_addr, 4);
						fin_pkt->writeData(14 + 20 + 0, &((struct sockaddr_in *)&connection->src_addr)->sin_port, 2);
						fin_pkt->writeData(14 + 20 + 2, &((struct sockaddr_in *)&connection->dst_addr)->sin_port, 2);
						fin_pkt->writeData(14 + 20 + 4, &packet_seq_num, 4);
						fin_pkt->writeData(14 + 20 + 8, &packet_ack_num, 4);
						fin_pkt->writeData(14 + 20 + 12, &packet_headerlen, 1);
						fin_pkt->writeData(14 + 20 + 13, &packet_flags, 1);
						fin_pkt->writeData(14 + 20 + 14, &packet_rwnd, 2);
						fin_pkt->writeData(14 + 20 + 16, &packet_checksum, 2);
						fin_pkt->writeData(14 + 20 + 18, &packet_pointer, 2);

						fin_pkt->readData(14 + 12, &source, sizeof(source));
						fin_pkt->readData(14 + 16, &dest, sizeof(dest));
						fin_pkt->readData(14 + 20, tcp_seg, sizeof(tcp_seg));

						packet_checksum = htons(0xFFFF - NetworkUtil::tcp_sum(source, dest, tcp_seg, sizeof(tcp_seg)));
						fin_pkt->writeData(14 + 20 + 16, &packet_checksum, 2);

						this->sendPacket("IPv4", fin_pkt);

						connection->tcp_state = TCP_FIN_WAIT_1;
					}
					else if(connection->tcp_state == TCP_CLOSE_WAIT)
					{
						connection->seq_num += 1;

						packet_seq_num = htonl(connection->seq_num);
						packet_ack_num = htonl(0x00000000);
						packet_headerlen = (uint8_t) 0x50;
						packet_flags = (uint8_t) FIN;
						packet_rwnd = (uint16_t) htons(51200);
						packet_checksum = (uint16_t) 0x0000;
						packet_pointer = (uint16_t) 0x0000;

						fin_pkt = this->allocatePacket(14 + 20 + 20);
						fin_pkt->writeData(14 + 12, &((struct sockaddr_in *)&connection->src_addr)->sin_addr.s_addr, 4);
						fin_pkt->writeData(14 + 16, &((struct sockaddr_in *)&connection->dst_addr)->sin_addr.s_addr, 4);
						fin_pkt->writeData(14 + 20 + 0, &((struct sockaddr_in *)&connection->src_addr)->sin_port, 2);
						fin_pkt->writeData(14 + 20 + 2, &((struct sockaddr_in *)&connection->dst_addr)->sin_port, 2);
						fin_pkt->writeData(14 + 20 + 4, &packet_seq_num, 4);
						fin_pkt->writeData(14 + 20 + 8, &packet_ack_num, 4);
						fin_pkt->writeData(14 + 20 + 12, &packet_headerlen, 1);
						fin_pkt->writeData(14 + 20 + 13, &packet_flags, 1);
						fin_pkt->writeData(14 + 20 + 14, &packet_rwnd, 2);
						fin_pkt->writeData(14 + 20 + 16, &packet_checksum, 2);
						fin_pkt->writeData(14 + 20 + 18, &packet_pointer, 2);

						fin_pkt->readData(14 + 12, &source, sizeof(source));
						fin_pkt->readData(14 + 16, &dest, sizeof(dest));
						fin_pkt->readData(14 + 20, tcp_seg, sizeof(tcp_seg));

						packet_checksum = htons(0xFFFF - NetworkUtil::tcp_sum(source, dest, tcp_seg, sizeof(tcp_seg)));
						fin_pkt->writeData(14 + 20 + 16, &packet_checksum, 2);

						this->sendPacket("IPv4", fin_pkt);

						connection->tcp_state = TCP_LAST_ACK;
					}
					else
						assert(0);
				}

				socket->uuid = syscallUUID;
			}
			break;

		case TCP_SYN_SENT:
			socket->connections.clear();
			fd_to_socket.erase(fd_to_pid);
			this->removeFileDescriptor(pid, fd);

			this->returnSystemCall(syscallUUID, 0);
			break;

		case TCP_ESTABLISHED:
			socket->seq_num += 1;

			packet_seq_num = htonl(socket->seq_num);
			packet_ack_num = htonl(0x00000000);
			packet_headerlen = (uint8_t) 0x50;
			packet_flags = (uint8_t) FIN;
			packet_rwnd = (uint16_t) htons(51200);
			packet_checksum = (uint16_t) 0x0000;
			packet_pointer = (uint16_t) 0x0000;

			fin_pkt = this->allocatePacket(14 + 20 + 20);
			fin_pkt->writeData(14 + 12, &((struct sockaddr_in *)&socket->src_addr)->sin_addr.s_addr, 4);
			fin_pkt->writeData(14 + 16, &((struct sockaddr_in *)&socket->dst_addr)->sin_addr.s_addr, 4);
			fin_pkt->writeData(14 + 20 + 0, &((struct sockaddr_in *)&socket->src_addr)->sin_port, 2);
			fin_pkt->writeData(14 + 20 + 2, &((struct sockaddr_in *)&socket->dst_addr)->sin_port, 2);
			fin_pkt->writeData(14 + 20 + 4, &packet_seq_num, 4);
			fin_pkt->writeData(14 + 20 + 8, &packet_ack_num, 4);
			fin_pkt->writeData(14 + 20 + 12, &packet_headerlen, 1);
			fin_pkt->writeData(14 + 20 + 13, &packet_flags, 1);
			fin_pkt->writeData(14 + 20 + 14, &packet_rwnd, 2);
			fin_pkt->writeData(14 + 20 + 16, &packet_checksum, 2);
			fin_pkt->writeData(14 + 20 + 18, &packet_pointer, 2);

			fin_pkt->readData(14 + 12, &source, sizeof(source));
			fin_pkt->readData(14 + 16, &dest, sizeof(dest));
			fin_pkt->readData(14 + 20, tcp_seg, sizeof(tcp_seg));
			
			packet_checksum = htons(0xFFFF - NetworkUtil::tcp_sum(source, dest, tcp_seg, sizeof(tcp_seg)));
			fin_pkt->writeData(14 + 20 + 16, &packet_checksum, 2);

			this->sendPacket("IPv4", fin_pkt);

			socket->tcp_state = TCP_FIN_WAIT_1;
			break;

		case TCP_CLOSE_WAIT:
			socket->seq_num += 1;

			packet_seq_num = htonl(socket->seq_num);
			packet_ack_num = htonl(0x00000000);
			packet_headerlen = (uint8_t) 0x50;
			packet_flags = (uint8_t) FIN;
			packet_rwnd = (uint16_t) htons(51200);
			packet_checksum = (uint16_t) 0x0000;
			packet_pointer = (uint16_t) 0x0000;

			fin_pkt = this->allocatePacket(14 + 20 + 20);
			fin_pkt->writeData(14 + 12, &((struct sockaddr_in *)&socket->src_addr)->sin_addr.s_addr, 4);
			fin_pkt->writeData(14 + 16, &((struct sockaddr_in *)&socket->dst_addr)->sin_addr.s_addr, 4);
			fin_pkt->writeData(14 + 20 + 0, &((struct sockaddr_in *)&socket->src_addr)->sin_port, 2);
			fin_pkt->writeData(14 + 20 + 2, &((struct sockaddr_in *)&socket->dst_addr)->sin_port, 2);
			fin_pkt->writeData(14 + 20 + 4, &packet_seq_num, 4);
			fin_pkt->writeData(14 + 20 + 8, &packet_ack_num, 4);
			fin_pkt->writeData(14 + 20 + 12, &packet_headerlen, 1);
			fin_pkt->writeData(14 + 20 + 13, &packet_flags, 1);
			fin_pkt->writeData(14 + 20 + 14, &packet_rwnd, 2);
			fin_pkt->writeData(14 + 20 + 16, &packet_checksum, 2);
			fin_pkt->writeData(14 + 20 + 18, &packet_pointer, 2);

			fin_pkt->readData(14 + 12, &source, sizeof(source));
			fin_pkt->readData(14 + 16, &dest, sizeof(dest));
			fin_pkt->readData(14 + 20, tcp_seg, sizeof(tcp_seg));
			
			packet_checksum = htons(0xFFFF - NetworkUtil::tcp_sum(source, dest, tcp_seg, sizeof(tcp_seg)));
			fin_pkt->writeData(14 + 20 + 16, &packet_checksum, 2);

			this->sendPacket("IPv4", fin_pkt);

			socket->tcp_state = TCP_LAST_ACK;
			break;

		default:
			socket->connections.clear();
			fd_to_socket.erase(fd_to_pid);
			this->removeFileDescriptor(pid, fd);

			this->returnSystemCall(syscallUUID, 0);
			break;
	}
}
/*
void TCPAssignment::syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int)
{

}


void TCPAssignment::syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int)
{

}
*/
void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd,
		struct sockaddr *addr, socklen_t addrlen)
{
	std::array<int, 2> fd_to_pid = {sockfd, pid};
	auto socket_iter = fd_to_socket.find(fd_to_pid);
	if(socket_iter == fd_to_socket.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	struct sock_info *c_socket = &socket_iter->second;
	if(c_socket->pid != pid)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	while(c_socket->bound_state != BOUND)
	{
		struct sockaddr_in src_addr;

		src_addr.sin_family = AF_INET;
		if (!getHost()->getIPAddr((uint8_t *)&src_addr.sin_addr.s_addr, getHost()->getRoutingTable ((const uint8_t *)&((struct sockaddr_in *)addr)->sin_addr.s_addr)))
		{
			this->returnSystemCall(syscallUUID, -1);
			return;
		}
		if(++implicit_bind_port > 65535)
			implicit_bind_port = 49152;
		src_addr.sin_port = implicit_bind_port;

		bool overlap = false;
		for(auto socket_iter = fd_to_socket.begin(); socket_iter != fd_to_socket.end(); ++socket_iter)
		{
			struct sock_info *socket = &socket_iter->second;

			if(socket->bound_state == UNBOUND)
				continue;

			if(((struct sockaddr_in *)&socket->src_addr)->sin_port == ((struct sockaddr_in *)&src_addr)->sin_port)
			{
				if(((struct sockaddr_in *)&socket->src_addr)->sin_addr.s_addr == htonl(INADDR_ANY))
				{
					overlap = true;
					break;
				}

				if(((struct sockaddr_in *)&src_addr)->sin_addr.s_addr == htonl(INADDR_ANY))
				{
					overlap = true;
					break;
				}

				if(((struct sockaddr_in *)&socket->src_addr)->sin_addr.s_addr == ((struct sockaddr_in *)&src_addr)->sin_addr.s_addr)
				{
					overlap = true;
					break;
				}
			}
		}

		if(!overlap)
		{
			c_socket->src_addr = *(sockaddr *)&src_addr;
			c_socket->bound_state = BOUND;
		}
	}

	c_socket->dst_addr = *addr;
	c_socket->seq_num += 1;

	uint32_t packet_seq_num = htonl(c_socket->seq_num);
	uint32_t packet_ack_num = htonl(0x00000000);
	uint8_t packet_headerlen = (uint8_t) 0x50;
	uint8_t packet_flags = (uint8_t) SYN;
	uint16_t packet_rwnd = (uint16_t) htons(51200);
	uint16_t packet_checksum = (uint16_t) 0x0000;
	uint16_t packet_pointer = (uint16_t) 0x0000;

	Packet *syn_pkt = this->allocatePacket(14 + 20 + 20);
	syn_pkt->writeData(14 + 12, &((struct sockaddr_in *)&c_socket->src_addr)->sin_addr.s_addr, 4);
	syn_pkt->writeData(14 + 16, &((struct sockaddr_in *)&c_socket->dst_addr)->sin_addr.s_addr, 4);
	syn_pkt->writeData(14 + 20 + 0, &((struct sockaddr_in *)&c_socket->src_addr)->sin_port, 2);
	syn_pkt->writeData(14 + 20 + 2, &((struct sockaddr_in *)&c_socket->dst_addr)->sin_port, 2);
	syn_pkt->writeData(14 + 20 + 4, &packet_seq_num, 4);
	syn_pkt->writeData(14 + 20 + 8, &packet_ack_num, 4);
	syn_pkt->writeData(14 + 20 + 12, &packet_headerlen, 1);
	syn_pkt->writeData(14 + 20 + 13, &packet_flags, 1);
	syn_pkt->writeData(14 + 20 + 14, &packet_rwnd, 2);
	syn_pkt->writeData(14 + 20 + 16, &packet_checksum, 2);
	syn_pkt->writeData(14 + 20 + 18, &packet_pointer, 2);

	uint32_t source, dest;
	uint8_t tcp_seg[20];
	syn_pkt->readData(14 + 12, &source, sizeof(source));
	syn_pkt->readData(14 + 16, &dest, sizeof(dest));
	syn_pkt->readData(14 + 20, tcp_seg, sizeof(tcp_seg));
	
	packet_checksum = htons(0xFFFF - NetworkUtil::tcp_sum(source, dest, tcp_seg, sizeof(tcp_seg)));
	syn_pkt->writeData(14 + 20 + 16, &packet_checksum, 2);

	this->sendPacket("IPv4", syn_pkt);
	c_socket->tcp_state = TCP_SYN_SENT;

	c_socket->uuid = syscallUUID;
	return;
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog)
{
	std::array<int, 2> fd_to_pid = {sockfd, pid};
	auto socket_iter = fd_to_socket.find(fd_to_pid);
	if(socket_iter == fd_to_socket.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	struct sock_info *socket = &socket_iter->second;

	if(socket->bound_state != BOUND || socket->tcp_state != TCP_CLOSED)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	socket->tcp_state = TCP_LISTEN;
	socket->backlog = backlog;

	this->returnSystemCall(syscallUUID, 0);
	return;
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd,
		struct sockaddr *addr,
		socklen_t *addrlen)
{
	std::array<int, 2> fd_to_pid = {sockfd, pid};
	auto socket_iter = fd_to_socket.find(fd_to_pid);
	if(socket_iter == fd_to_socket.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	struct sock_info *l_socket = &socket_iter->second;

	if(l_socket->tcp_state != TCP_LISTEN)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	struct connection *connection;
	auto connection_iter = l_socket->connections.begin();
	bool found = false;
	for(; connection_iter != l_socket->connections.end(); ++connection_iter)
	{
		connection = &*connection_iter;
		if(connection->connection_state == CONNECTED)
		{
			found = true;
			break;
		}
	}

	if(found)
	{
		int fd = this->createFileDescriptor(pid);
		if(fd == -1)
		{
			this->returnSystemCall(syscallUUID, -1);
			return;
		}

		std::array<int, 2> fd_to_pid = {fd, pid};

		if(fd_to_socket.find(fd_to_pid) != fd_to_socket.end())
		{
			this->returnSystemCall(syscallUUID, -1);
			return;
		}

		struct sock_info s_socket;
		s_socket.uuid = 0;
		s_socket.pid = pid;
		s_socket.src_addr = connection->src_addr;
		s_socket.dst_addr = connection->dst_addr;
		s_socket.bound_state = BOUND;
		s_socket.connection_state = connection->connection_state;
		s_socket.tcp_state = connection->tcp_state;
		s_socket.backlog = 0;
		s_socket.seq_num = connection->seq_num;
		s_socket.ack_num = connection->ack_num;
		s_socket.accept_called = false;
		s_socket.accept_addr = NULL;
		s_socket.accept_addrlen = NULL;

		l_socket->connections.erase(connection_iter);
		fd_to_socket.insert(std::pair<std::array<int, 2>, sock_info>(fd_to_pid, s_socket));

		*addr = s_socket.dst_addr;
		*addrlen = sizeof (*addr);

		this->returnSystemCall(syscallUUID, fd);
		return;
	}
	else
	{
		l_socket->accept_called = true;
		l_socket->accept_addr = addr;
		l_socket->accept_addrlen = addrlen;

		l_socket->uuid = syscallUUID;
		return;
	}
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd,
		struct sockaddr *addr,
		socklen_t addrlen)
{
	std::array<int, 2> fd_to_pid = {sockfd, pid};
	for(auto socket_iter = fd_to_socket.begin(); socket_iter != fd_to_socket.end(); ++socket_iter)
	{
		struct sock_info *socket = &socket_iter->second;

		if(socket->bound_state == UNBOUND)
			continue;

		if(((struct sockaddr_in *)&socket->src_addr)->sin_port == ((struct sockaddr_in *)addr)->sin_port)
		{
			if(((struct sockaddr_in *)&socket->src_addr)->sin_addr.s_addr == htonl(INADDR_ANY))
			{
				this->returnSystemCall(syscallUUID, -1);
				return;
			}

			if(((struct sockaddr_in *)addr)->sin_addr.s_addr == htonl(INADDR_ANY))
			{
				this->returnSystemCall(syscallUUID, -1);
				return;
			}

			if(((struct sockaddr_in *)&socket->src_addr)->sin_addr.s_addr == ((struct sockaddr_in *)addr)->sin_addr.s_addr)
			{
				this->returnSystemCall(syscallUUID, -1);
				return;
			}
		}
	}

	auto socket_iter = fd_to_socket.find(fd_to_pid);
	
	if(socket_iter == fd_to_socket.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	
	struct sock_info *socket = &socket_iter->second;
	
	if(socket->bound_state == BOUND)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	socket->src_addr = *addr;
	socket->bound_state = BOUND;

	this->returnSystemCall(syscallUUID, 0);
	return;
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd,
		struct sockaddr *addr,
		socklen_t *addrlen)
{
	std::array<int, 2> fd_to_pid = {sockfd, pid};
	auto socket_iter = fd_to_socket.find(fd_to_pid);
	if(socket_iter == fd_to_socket.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	struct sock_info *socket = &socket_iter->second;
	
	if(socket->bound_state != BOUND)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;	
	}

	*addr = socket->src_addr;
	*addrlen = sizeof(*addr);

	this->returnSystemCall(syscallUUID, 0);
	return;
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd,
		struct sockaddr *addr,
		socklen_t *addrlen)
{
	std::array<int, 2> fd_to_pid = {sockfd, pid};
	auto socket_iter = fd_to_socket.find(fd_to_pid);
	if(socket_iter == fd_to_socket.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	struct sock_info *socket = &socket_iter->second;
	
	if(socket->connection_state != CONNECTED)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;	
	}

	*addr = socket->dst_addr;
	*addrlen = sizeof(*addr);

	this->returnSystemCall(syscallUUID, 0);
	return;
}

}

