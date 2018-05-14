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
		this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
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
	uint16_t total_len;
	uint16_t payload_len;
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_num;
	uint32_t ack_num;
	uint8_t head_len;
	uint8_t flags;
	uint16_t rwnd;
	uint16_t urg_ptr;

	uint32_t src_ip, dst_ip;
	uint8_t tcp_seg[packet->getSize() - 34];
	packet->readData(14 + 12, &src_ip, sizeof(src_ip));
	packet->readData(14 + 16, &dst_ip, sizeof(dst_ip));
	packet->readData(14 + 20, tcp_seg, sizeof(tcp_seg));

	if(NetworkUtil::tcp_sum(src_ip, dst_ip, tcp_seg, sizeof(tcp_seg)) != 0xFFFF)
	{
		this->freePacket(packet);
		return;
	}

	packet->readData(14 + 2, &total_len, sizeof(total_len));
	packet->readData(14 + 20 + 0, &src_port, sizeof(src_port));
	packet->readData(14 + 20 + 2, &dst_port, sizeof(dst_port));
	packet->readData(14 + 20 + 4, &seq_num, sizeof(seq_num));
	packet->readData(14 + 20 + 8, &ack_num, sizeof(ack_num));
	packet->readData(14 + 20 + 12, &head_len, sizeof(head_len));
	packet->readData(14 + 20 + 13, &flags, sizeof(flags));
	packet->readData(14 + 20 + 14, &rwnd, sizeof(rwnd));
	packet->readData(14 + 20 + 18, &urg_ptr, sizeof(urg_ptr));
	payload_len = ntohs(total_len) - 20 - 20;
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
	
	switch(rcv_socket->tcp_state)
	{
		case TCP_LISTEN:
			if(flags == SYN)
			{
				int connection_count = 0;
				for(auto connection_iter = rcv_socket->connections.begin(); connection_iter != rcv_socket->connections.end(); ++connection_iter)
				{
					struct connection *connection_temp = &*connection_iter;
					if(connection_temp->tcp_state == TCP_SYN_RCVD)
						connection_count++;
				}

				if(rcv_socket->backlog <= connection_count)
					break;

				struct connection connection;
				connection.src_addr = *(sockaddr *)&dst_addr;
				connection.dst_addr = *(sockaddr *)&src_addr;
				connection.tcp_state = TCP_SYN_RCVD;
				connection.seq_num = initial_seq_num++;
				connection.ack_num = seq_num + 1;
				rcv_socket->connections.push_back(connection);

				send_packet(20 + 20, dst_ip, src_ip, dst_port, src_port, connection.seq_num, connection.ack_num, SYNACK, BUF_SIZE - connection.rb.size, NULL);

				struct connection *connection_temp = &*(--rcv_socket->connections.end());
				connection_temp->seq_num += 1;
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

				if(connection->seq_num == ack_num)
				{
					if(connection->tcp_state == TCP_SYN_RCVD)
					{
						connection->tcp_state = TCP_ESTABLISHED;

						if(rcv_socket->accept_called)
						{
							int fd = this->createFileDescriptor(rcv_socket->pid);
							if(fd == -1)
							{
								this->returnSystemCall(rcv_socket->uuid, -1);
								return;
							}

							std::array<int, 2> fd_to_pid = {{fd, rcv_socket->pid}};

							if(fd_to_socket.find(fd_to_pid) != fd_to_socket.end())
							{
								this->returnSystemCall(rcv_socket->uuid, -1);
								return;
							}

							struct sock_info s_socket;
							static struct write_buffer empty_wb;
							static struct write_manager empty_wmgr;
							s_socket.uuid = 0;
							s_socket.pid = rcv_socket->pid;
							s_socket.src_addr = connection->src_addr;
							s_socket.dst_addr = connection->dst_addr;
							s_socket.bound_state = BOUND;
							s_socket.connection_state = CONNECTED;
							s_socket.close_state = UNCLOSED;
							s_socket.tcp_state = connection->tcp_state;
							s_socket.backlog = 0;
							s_socket.seq_num = connection->seq_num;
							s_socket.ack_num = connection->ack_num;
							s_socket.accept_called = false;
							s_socket.accept_addr = NULL;
							s_socket.accept_addrlen = NULL;
							s_socket.rmgr = connection->rmgr;
							s_socket.rb = connection->rb;
							s_socket.read_called = false;
							s_socket.read_buf = NULL;
							s_socket.read_count = 0;
							s_socket.wmgr = empty_wmgr;
							s_socket.wb = empty_wb;
							s_socket.write_called = false;
							s_socket.write_buf = NULL;
							s_socket.write_count = 0;
							s_socket.smallest_unacked = s_socket.seq_num;
							s_socket.rwnd = BUF_SIZE;
							s_socket.dup_ack_count = 0;
							s_socket.retransmit_timer = NULL;

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
					else if(connection->tcp_state == TCP_ESTABLISHED)
					{
						if(payload_len > 0)
						{
							if(connection->ack_num >= seq_num)
							{
								uint8_t payload[MSS];
								packet->readData(14 + 20 + 20, payload, payload_len);
								rb_write(&connection->rb, connection->rb.cont_end + seq_num - connection->ack_num, payload, payload_len);

								struct read_info ri;
								ri.start = connection->rb.cont_end + seq_num - connection->ack_num;
								ri.end = ri.start + payload_len;
								ri.size = payload_len;

								connection->rmgr.read_infos.push_back(ri);
								connection->rmgr.read_infos.sort(asc_seq);
								connection->rmgr.start = ri.start >= connection->rmgr.start ? connection->rmgr.start : ri.start;
								connection->rmgr.end = ri.end <= connection->rmgr.end ? connection->rmgr.end : ri.end;
								connection->rmgr.size = (connection->rmgr.end  + BUF_SIZE + 1 - connection->rmgr.start) % (BUF_SIZE + 1);

								while(!connection->rmgr.read_infos.empty())
								{
									if(connection->rb.cont_end == (*connection->rmgr.read_infos.begin()).start)
									{
										connection->ack_num = (*connection->rmgr.read_infos.begin()).seq_num + (*connection->rmgr.read_infos.begin()).size;
										connection->rb.cont_end = (*connection->rmgr.read_infos.begin()).end;
										connection->rb.cont_size += (*connection->rmgr.read_infos.begin()).size;
										connection->rmgr.start = (*connection->rmgr.read_infos.begin()).start;
										connection->rmgr.size -= (*connection->rmgr.read_infos.begin()).size;
										connection->rmgr.read_infos.pop_front();
									}
									else
										break;
								}
							}

							send_packet(20 + 20, dst_ip, src_ip, dst_port, src_port, connection->seq_num, connection->ack_num, ACK, BUF_SIZE - connection->rb.size, NULL);
						}
					}
					else if(connection->tcp_state == TCP_LAST_ACK)
					{
						rcv_socket->connections.erase(connection_iter);
						if(rcv_socket->connections.empty())
						{
							UUID temp_uuid = rcv_socket->uuid;
							int temp_pid = rcv_socket->pid;
							std::array<int, 2> fd_to_pid = {{rcv_fd, temp_pid}};
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
						timer->type = PAYLOAD_CONNECTION;
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

					send_packet(20 + 20, dst_ip, src_ip, dst_port, src_port, connection->seq_num, connection->ack_num, ACK, BUF_SIZE - connection->rb.size, NULL);

					connection->tcp_state = TCP_CLOSE_WAIT;
				}
				else if(connection->tcp_state == TCP_FIN_WAIT_1)
				{
					connection->ack_num = seq_num + 1;

					send_packet(20 + 20, dst_ip, src_ip, dst_port, src_port, connection->seq_num, connection->ack_num, ACK, BUF_SIZE - connection->rb.size, NULL);

					connection->tcp_state = TCP_CLOSING;
				}
				else if(connection->tcp_state == TCP_FIN_WAIT_2)
				{
					connection->ack_num = seq_num + 1;

					send_packet(20 + 20, dst_ip, src_ip, dst_port, src_port, connection->seq_num, connection->ack_num, ACK, BUF_SIZE - connection->rb.size, NULL);

					connection->tcp_state = TCP_TIME_WAIT;
						
					struct timer_payload *timer = new struct timer_payload;
					timer->type = PAYLOAD_CONNECTION;
					timer->socket = rcv_socket;
					timer->connection = connection;

					timer->uuid = addTimer(timer, TimeUtil::makeTime(60, TimeUtil::SEC));
				}
			}
			break;

		case TCP_SYN_SENT:
			if(flags == SYN)
			{
				rcv_socket->seq_num -= 1;
				rcv_socket->ack_num = seq_num + 1;

				send_packet(20 + 20, dst_ip, src_ip, dst_port, src_port, rcv_socket->seq_num, rcv_socket->ack_num, SYNACK, BUF_SIZE - rcv_socket->rb.size, NULL);

				rcv_socket->seq_num += 1;
			}
			else if(flags == SYNACK)
			{
				if(rcv_socket->seq_num == ack_num)
				{
					rcv_socket->ack_num = seq_num + 1;

					send_packet(20 + 20, dst_ip, src_ip, dst_port, src_port, rcv_socket->seq_num, rcv_socket->ack_num, ACK, BUF_SIZE - rcv_socket->rb.size, NULL);

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

				send_packet(20 + 20, dst_ip, src_ip, dst_port, src_port, rcv_socket->seq_num, rcv_socket->ack_num, ACK, BUF_SIZE - rcv_socket->rb.size, NULL);

				rcv_socket->tcp_state = TCP_CLOSE_WAIT;
			}
			else if(flags == ACK)
			{
				if(payload_len > 0)
				{
					if(rcv_socket->ack_num <= seq_num)
					{
						uint8_t payload[MSS];
						packet->readData(14 + 20 + 20, payload, payload_len);
						rb_write(&rcv_socket->rb, rcv_socket->rb.cont_end + seq_num - rcv_socket->ack_num, payload, payload_len);

						struct read_info ri;
						ri.start = rcv_socket->rb.cont_end + seq_num - rcv_socket->ack_num;
						ri.end = ri.start + payload_len;
						ri.size = payload_len;

						rcv_socket->rmgr.read_infos.push_back(ri);
						rcv_socket->rmgr.read_infos.sort(asc_seq);
						rcv_socket->rmgr.start = ri.start >= rcv_socket->rmgr.start ? rcv_socket->rmgr.start : ri.start;
						rcv_socket->rmgr.end = ri.end <= rcv_socket->rmgr.end ? rcv_socket->rmgr.end : ri.end;
						rcv_socket->rmgr.size = (rcv_socket->rmgr.end + BUF_SIZE + 1 - rcv_socket->rmgr.start) % (BUF_SIZE + 1);

						while(!rcv_socket->rmgr.read_infos.empty())
						{
							if(rcv_socket->rb.cont_end == (*rcv_socket->rmgr.read_infos.begin()).start)
							{
								rcv_socket->ack_num = (*rcv_socket->rmgr.read_infos.begin()).seq_num + (*rcv_socket->rmgr.read_infos.begin()).size;
								rcv_socket->rb.cont_end = (*rcv_socket->rmgr.read_infos.begin()).end;
								rcv_socket->rb.cont_size += (*rcv_socket->rmgr.read_infos.begin()).size;
								rcv_socket->rmgr.start = (*rcv_socket->rmgr.read_infos.begin()).start;
								rcv_socket->rmgr.size -= (*rcv_socket->rmgr.read_infos.begin()).size;
								rcv_socket->rmgr.read_infos.pop_front();
							}
							else
								break;
						}
					}

					send_packet(20 + 20, dst_ip, src_ip, dst_port, src_port, rcv_socket->seq_num, rcv_socket->ack_num, ACK, BUF_SIZE - rcv_socket->rb.size, NULL);
				
					if(rcv_socket->read_called)
					{
						if(rcv_socket->rb.cont_size > 0)
						{
							size_t read_count = rb_read(&rcv_socket->rb, rcv_socket->read_buf, rcv_socket->read_count);

							rcv_socket->rb.start = (rcv_socket->rb.start + read_count) % (BUF_SIZE + 1);
							rcv_socket->rb.size -= read_count;

							this->returnSystemCall(rcv_socket->uuid, read_count);
						}
					}
				}
				else
				{
					if(rcv_socket->smallest_unacked == ack_num)
					{
						rcv_socket->dup_ack_count++;
						if(rcv_socket->dup_ack_count >= 3)
						{
							cancelTimer((rcv_socket->retransmit_timer)->uuid);
							delete(rcv_socket->retransmit_timer);
							rcv_socket->retransmit_timer = NULL;

							rcv_socket->dup_ack_count = 0;

							struct write_manager wmgr = rcv_socket->wmgr;
							for(auto wi_iter = wmgr.write_infos.begin(); wi_iter != wmgr.write_infos.end(); ++wi_iter)
							{
								struct write_info *wi = &*wi_iter;

								uint8_t payload[MSS];
								size_t read_count = wb_read(&rcv_socket->wb, wi->start, payload, wi->size);

								send_packet(20 + 20 + read_count, dst_ip, src_ip, dst_port, src_port, wi->seq_num, 0x00000000, ACK, BUF_SIZE - rcv_socket->rb.size, payload);
							}

							struct timer_payload *timer = new struct timer_payload;
							timer->type = PAYLOAD_PACKET;
							timer->socket = rcv_socket;
							rcv_socket->retransmit_timer = timer;

							rcv_socket->retransmit_timer->uuid = addTimer(rcv_socket->retransmit_timer, TimeUtil::makeTime(100, TimeUtil::MSEC));
						}
					}
					else
					{
						rcv_socket->smallest_unacked = ack_num;
						rcv_socket->dup_ack_count = 0;

						while(!rcv_socket->wmgr.write_infos.empty())
						{
							auto wi_iter = rcv_socket->wmgr.write_infos.begin();
							struct write_info *wi = &*wi_iter;
							if(wi->seq_num == ack_num)
								break;
							else
							{
								rcv_socket->wb.start = wi->end;
								rcv_socket->wb.size -= wi->size;
								rcv_socket->wmgr.start = wi->end;
								rcv_socket->wmgr.size -= wi->size;
								rcv_socket->wmgr.write_infos.pop_front();
							}
						}

						cancelTimer(rcv_socket->retransmit_timer->uuid);
						delete(rcv_socket->retransmit_timer);
						rcv_socket->retransmit_timer = NULL;

						if(rcv_socket->write_called)
						{
							if(rcv_socket->write_count <= BUF_SIZE - rcv_socket->wb.size)
							{
								size_t write_count = wb_write(&rcv_socket->wb, rcv_socket->write_buf, rcv_socket->write_count);

								rcv_socket->write_called = false;
								rcv_socket->write_buf = NULL;
								rcv_socket->write_count = 0;

								this->returnSystemCall(rcv_socket->uuid, write_count);
							}
						}

						if(rcv_socket->rwnd >= rcv_socket->wmgr.size)
						{
							uint32_t seg_len;
							while(rcv_socket->wb.size > rcv_socket->wmgr.size)
							{
								seg_len = rcv_socket->wb.size - rcv_socket->wmgr.size >= MSS ? MSS : rcv_socket->wb.size - rcv_socket->wmgr.size;

								struct write_info wi;
								wi.start = rcv_socket->wmgr.end;
								wi.end = (wi.start + seg_len) % (BUF_SIZE + 1);
								wi.size = seg_len;
								wi.seq_num = rcv_socket->seq_num;

								uint8_t payload[MSS];
								size_t read_count = wb_read(&rcv_socket->wb, wi.start, payload, wi.size);

								send_packet(20 + 20 + read_count, dst_ip, src_ip, dst_port, src_port, wi.seq_num, 0x00000000, ACK, BUF_SIZE - rcv_socket->rb.size, payload);

								if(rcv_socket->wmgr.write_infos.empty())
								{
									struct timer_payload *timer = new struct timer_payload;
									timer->type = PAYLOAD_PACKET;
									timer->socket = rcv_socket;
									rcv_socket->retransmit_timer = timer;

									timer->uuid = addTimer(timer, TimeUtil::makeTime(100, TimeUtil::MSEC));
								}

								rcv_socket->wmgr.write_infos.push_back(wi);
								rcv_socket->wmgr.end = wi.end;
								rcv_socket->wmgr.size += wi.size;
								rcv_socket->seq_num += wi.size;
							}
						}
					}
				}
			}
			break;

		case TCP_CLOSE_WAIT:
			if(flags == ACK)
			{
				if(payload_len == 0)
				{
					if(rcv_socket->smallest_unacked == ack_num)
					{
						rcv_socket->dup_ack_count++;
						if(rcv_socket->dup_ack_count >= 3)
						{
							cancelTimer((rcv_socket->retransmit_timer)->uuid);
							delete(rcv_socket->retransmit_timer);
							rcv_socket->retransmit_timer = NULL;

							rcv_socket->dup_ack_count = 0;

							struct write_manager wmgr = rcv_socket->wmgr;
							for(auto wi_iter = wmgr.write_infos.begin(); wi_iter != wmgr.write_infos.end(); ++wi_iter)
							{
								struct write_info *wi = &*wi_iter;

								uint8_t payload[MSS];
								size_t read_count = wb_read(&rcv_socket->wb, wi->start, payload, wi->size);

								send_packet(20 + 20 + read_count, dst_ip, src_ip, dst_port, src_port, wi->seq_num, 0x00000000, ACK, BUF_SIZE - rcv_socket->rb.size, payload);
							}

							struct timer_payload *timer = new struct timer_payload;
							timer->type = PAYLOAD_PACKET;
							timer->socket = rcv_socket;
							rcv_socket->retransmit_timer = timer;

							rcv_socket->retransmit_timer->uuid = addTimer(rcv_socket->retransmit_timer, TimeUtil::makeTime(100, TimeUtil::MSEC));
						}
					}
					else
					{
						rcv_socket->smallest_unacked = ack_num;
						rcv_socket->dup_ack_count = 0;

						while(!rcv_socket->wmgr.write_infos.empty())
						{
							auto wi_iter = rcv_socket->wmgr.write_infos.begin();
							struct write_info *wi = &*wi_iter;
							if(wi->seq_num == ack_num)
								break;
							else
							{
								rcv_socket->wb.start = wi->end;
								rcv_socket->wb.size -= wi->size;
								rcv_socket->wmgr.start = wi->end;
								rcv_socket->wmgr.size -= wi->size;
								rcv_socket->wmgr.write_infos.pop_front();
							}
						}

						cancelTimer(rcv_socket->retransmit_timer->uuid);
						delete(rcv_socket->retransmit_timer);
						rcv_socket->retransmit_timer = NULL;

						if(rcv_socket->rwnd >= rcv_socket->wmgr.size)
						{
							uint32_t seg_len;
							while(rcv_socket->wb.size > rcv_socket->wmgr.size)
							{
								seg_len = rcv_socket->wb.size - rcv_socket->wmgr.size >= MSS ? MSS : rcv_socket->wb.size - rcv_socket->wmgr.size;

								struct write_info wi;
								wi.start = rcv_socket->wmgr.end;
								wi.end = (wi.start + seg_len) % (BUF_SIZE + 1);
								wi.size = seg_len;
								wi.seq_num = rcv_socket->seq_num;

								uint8_t payload[MSS];
								size_t read_count = wb_read(&rcv_socket->wb, wi.start, payload, wi.size);

								send_packet(20 + 20 + read_count, dst_ip, src_ip, dst_port, src_port, wi.seq_num, 0x00000000, ACK, BUF_SIZE - rcv_socket->rb.size, payload);

								if(rcv_socket->wmgr.write_infos.empty())
								{
									struct timer_payload *timer = new struct timer_payload;
									timer->type = PAYLOAD_PACKET;
									timer->socket = rcv_socket;
									rcv_socket->retransmit_timer = timer;

									timer->uuid = addTimer(timer, TimeUtil::makeTime(100, TimeUtil::MSEC));
								}

								rcv_socket->wmgr.write_infos.push_back(wi);
								rcv_socket->wmgr.end = wi.end;
								rcv_socket->wmgr.size += wi.size;
								rcv_socket->seq_num += wi.size;
							}
						}
					}
				}
			}

		case TCP_LAST_ACK:
			if(flags == ACK)
			{
				int temp_pid = rcv_socket->pid;

				rcv_socket->seq_num = ack_num;
				rcv_socket->connections.clear();
				std::array<int, 2> fd_to_pid = {{rcv_fd, rcv_socket->pid}};
				fd_to_socket.erase(fd_to_pid);
				this->removeFileDescriptor(temp_pid, rcv_fd);
			}
			break;

		case TCP_FIN_WAIT_1:
			if(flags == ACK)
			{
				if(payload_len > 0)
				{
					if(rcv_socket->ack_num <= seq_num)
					{
						uint8_t payload[MSS];
						packet->readData(14 + 20 + 20, payload, payload_len);
						rb_write(&rcv_socket->rb, rcv_socket->rb.cont_end + seq_num - rcv_socket->ack_num, payload, payload_len);

						struct read_info ri;
						ri.start = rcv_socket->rb.cont_end + seq_num - rcv_socket->ack_num;
						ri.end = ri.start + payload_len;
						ri.size = payload_len;

						rcv_socket->rmgr.read_infos.push_back(ri);
						rcv_socket->rmgr.read_infos.sort(asc_seq);
						rcv_socket->rmgr.start = ri.start >= rcv_socket->rmgr.start ? rcv_socket->rmgr.start : ri.start;
						rcv_socket->rmgr.end = ri.end <= rcv_socket->rmgr.end ? rcv_socket->rmgr.end : ri.end;
						rcv_socket->rmgr.size = (rcv_socket->rmgr.end + BUF_SIZE + 1 - rcv_socket->rmgr.start) % (BUF_SIZE + 1);

						while(!rcv_socket->rmgr.read_infos.empty())
						{
							if(rcv_socket->rb.cont_end == (*rcv_socket->rmgr.read_infos.begin()).start)
							{
								rcv_socket->ack_num = (*rcv_socket->rmgr.read_infos.begin()).seq_num + (*rcv_socket->rmgr.read_infos.begin()).size;
								rcv_socket->rb.cont_end = (*rcv_socket->rmgr.read_infos.begin()).end;
								rcv_socket->rb.cont_size += (*rcv_socket->rmgr.read_infos.begin()).size;
								rcv_socket->rmgr.start = (*rcv_socket->rmgr.read_infos.begin()).start;
								rcv_socket->rmgr.size -= (*rcv_socket->rmgr.read_infos.begin()).size;
								rcv_socket->rmgr.read_infos.pop_front();
							}
							else
								break;
						}
					}

					send_packet(20 + 20, dst_ip, src_ip, dst_port, src_port, rcv_socket->seq_num, rcv_socket->ack_num, ACK, BUF_SIZE - rcv_socket->rb.size, NULL);
				}
				else
				{
					if(rcv_socket->seq_num == ack_num)
						rcv_socket->tcp_state = TCP_FIN_WAIT_2;
				}
			}
			else if(flags == FIN)
			{
				rcv_socket->ack_num = seq_num + 1;

				send_packet(20 + 20, dst_ip, src_ip, dst_port, src_port, rcv_socket->seq_num, rcv_socket->ack_num, ACK, BUF_SIZE - rcv_socket->rb.size, NULL);

				rcv_socket->tcp_state = TCP_CLOSING;
			}
			break;

		case TCP_FIN_WAIT_2:
			if(flags == ACK)
			{
				if(payload_len > 0)
				{
					if(rcv_socket->ack_num <= seq_num)
					{
						uint8_t payload[MSS];
						packet->readData(14 + 20 + 20, payload, payload_len);
						rb_write(&rcv_socket->rb, rcv_socket->rb.cont_end + seq_num - rcv_socket->ack_num, payload, payload_len);

						struct read_info ri;
						ri.start = rcv_socket->rb.cont_end + seq_num - rcv_socket->ack_num;
						ri.end = ri.start + payload_len;
						ri.size = payload_len;

						rcv_socket->rmgr.read_infos.push_back(ri);
						rcv_socket->rmgr.read_infos.sort(asc_seq);
						rcv_socket->rmgr.start = ri.start >= rcv_socket->rmgr.start ? rcv_socket->rmgr.start : ri.start;
						rcv_socket->rmgr.end = ri.end <= rcv_socket->rmgr.end ? rcv_socket->rmgr.end : ri.end;
						rcv_socket->rmgr.size = (rcv_socket->rmgr.end + BUF_SIZE + 1 - rcv_socket->rmgr.start) % (BUF_SIZE + 1);

						while(!rcv_socket->rmgr.read_infos.empty())
						{
							if(rcv_socket->rb.cont_end == (*rcv_socket->rmgr.read_infos.begin()).start)
							{
								rcv_socket->ack_num = (*rcv_socket->rmgr.read_infos.begin()).seq_num + (*rcv_socket->rmgr.read_infos.begin()).size;
								rcv_socket->rb.cont_end = (*rcv_socket->rmgr.read_infos.begin()).end;
								rcv_socket->rb.cont_size += (*rcv_socket->rmgr.read_infos.begin()).size;
								rcv_socket->rmgr.start = (*rcv_socket->rmgr.read_infos.begin()).start;
								rcv_socket->rmgr.size -= (*rcv_socket->rmgr.read_infos.begin()).size;
								rcv_socket->rmgr.read_infos.pop_front();
							}
							else
								break;
						}
					}

					send_packet(20 + 20, dst_ip, src_ip, dst_port, src_port, rcv_socket->seq_num, rcv_socket->ack_num, ACK, BUF_SIZE - rcv_socket->rb.size, NULL);
				}
			}
			else if(flags == FIN)
			{
				rcv_socket->ack_num = seq_num + 1;

				send_packet(20 + 20, dst_ip, src_ip, dst_port, src_port, rcv_socket->seq_num, rcv_socket->ack_num, ACK, BUF_SIZE - rcv_socket->rb.size, NULL);

				rcv_socket->tcp_state = TCP_TIME_WAIT;

				struct timer_payload *timer = new struct timer_payload;
				timer->type = PAYLOAD_SOCKET;
				timer->socket = rcv_socket;

				timer->uuid = addTimer(timer, TimeUtil::makeTime(60, TimeUtil::SEC));
			}
			break; 

		case TCP_CLOSING:
			if(flags == ACK)
			{
				if(rcv_socket->seq_num == ack_num)
				{
					rcv_socket->tcp_state = TCP_TIME_WAIT;

					struct timer_payload *timer = new struct timer_payload;
					timer->type = PAYLOAD_SOCKET;
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

	if(timer->type == PAYLOAD_SOCKET)
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
			return;

		socket->connections.clear();
		std::array<int, 2> fd_to_pid = {{fd, socket->pid}};
		fd_to_socket.erase(fd_to_pid);
		this->removeFileDescriptor(socket->pid, fd);

		this->returnSystemCall(socket->uuid, 0);
	}
	else if(timer->type == PAYLOAD_CONNECTION)
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
			std::array<int, 2> fd_to_pid = {{fd, socket->pid}};
			fd_to_socket.erase(fd_to_pid);
			this->removeFileDescriptor(socket->pid, fd);

			this->returnSystemCall(socket->uuid, 0);
		}
	}
	else if(timer->type == PAYLOAD_PACKET)
	{
		struct sock_info *socket = timer->socket;
		socket->dup_ack_count = 0;

		struct write_manager wmgr = socket->wmgr;
		for(auto wi_iter = wmgr.write_infos.begin(); wi_iter != wmgr.write_infos.end(); ++wi_iter)
		{
			struct write_info *wi = &*wi_iter;

			uint8_t payload[MSS];
			size_t read_count = wb_read(&socket->wb, wi->start, payload, wi->size);

			send_packet(20 + 20 + read_count, ((struct sockaddr_in *)&socket->src_addr)->sin_addr.s_addr, ((struct sockaddr_in *)&socket->dst_addr)->sin_addr.s_addr, ((struct sockaddr_in *)&socket->src_addr)->sin_port, ((struct sockaddr_in *)&socket->dst_addr)->sin_port, wi->seq_num, 0x00000000, ACK, BUF_SIZE - socket->rb.size, payload);
		}

		struct timer_payload *retransmit_timer = new struct timer_payload;
		timer->type = PAYLOAD_PACKET;
		timer->socket = socket;
		socket->retransmit_timer = retransmit_timer;

		socket->retransmit_timer->uuid = addTimer(socket->retransmit_timer, TimeUtil::makeTime(100, TimeUtil::MSEC));
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

	std::array<int, 2> fd_to_pid = {{fd, pid}};
	
	struct sock_info socket;
	static struct sockaddr empty_addr;
	static struct read_buffer empty_rb;
	static struct write_buffer empty_wb;
	static struct read_manager empty_rmgr;
	static struct write_manager empty_wmgr;
	socket.uuid = 0;
	socket.pid = pid;
	socket.src_addr = empty_addr;
	socket.dst_addr = empty_addr;
	socket.bound_state = UNBOUND;
	socket.connection_state = UNCONNECTED;
	socket.close_state = UNCLOSED;
	socket.tcp_state = TCP_CLOSED;
	socket.backlog = 0;
	socket.seq_num = initial_seq_num++;
	socket.ack_num = 0x00000000;
	socket.accept_called = false;
	socket.accept_addr = NULL;
	socket.accept_addrlen = NULL;
	socket.rmgr = empty_rmgr;
	socket.rb = empty_rb;
	socket.read_called = false;
	socket.read_buf = NULL;
	socket.read_count = 0;
	socket.wmgr = empty_wmgr;
	socket.wb = empty_wb;
	socket.write_called = false;
	socket.write_buf = NULL;
	socket.write_count = 0;
	socket.smallest_unacked = socket.seq_num;
	socket.rwnd = BUF_SIZE;
	socket.dup_ack_count = 0;
	socket.retransmit_timer = NULL;

	fd_to_socket.insert(std::pair<std::array<int, 2>, sock_info>(fd_to_pid, socket));

	this->returnSystemCall(syscallUUID, fd);
	return;
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd)
{
	std::array<int , 2> fd_to_pid = {{fd, pid}};
	auto socket_iter = fd_to_socket.find(fd_to_pid);
	if(socket_iter == fd_to_socket.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	struct sock_info *socket = &socket_iter->second;

	socket->close_state = CLOSED;

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
						send_packet(20 + 20, ((struct sockaddr_in *)&connection->src_addr)->sin_addr.s_addr, ((struct sockaddr_in *)&connection->dst_addr)->sin_addr.s_addr, ((struct sockaddr_in *)&connection->src_addr)->sin_port, ((struct sockaddr_in *)&connection->dst_addr)->sin_port, connection->seq_num, 0x00000000, FIN, BUF_SIZE - connection->rb.size, NULL);

						connection->seq_num += 1;
						connection->tcp_state = TCP_FIN_WAIT_1;
					}
					else if(connection->tcp_state == TCP_CLOSE_WAIT)
					{
						send_packet(20 + 20, ((struct sockaddr_in *)&connection->src_addr)->sin_addr.s_addr, ((struct sockaddr_in *)&connection->dst_addr)->sin_addr.s_addr, ((struct sockaddr_in *)&connection->src_addr)->sin_port, ((struct sockaddr_in *)&connection->dst_addr)->sin_port, connection->seq_num, 0x00000000, FIN, BUF_SIZE - connection->rb.size, NULL);

						connection->seq_num += 1;
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
			send_packet(20 + 20, ((struct sockaddr_in *)&socket->src_addr)->sin_addr.s_addr, ((struct sockaddr_in *)&socket->dst_addr)->sin_addr.s_addr, ((struct sockaddr_in *)&socket->src_addr)->sin_port, ((struct sockaddr_in *)&socket->dst_addr)->sin_port, socket->seq_num, 0x00000000, FIN, BUF_SIZE - socket->rb.size, NULL);

			socket->seq_num += 1;
			socket->tcp_state = TCP_FIN_WAIT_1;
			break;

		case TCP_CLOSE_WAIT:
			send_packet(20 + 20, ((struct sockaddr_in *)&socket->src_addr)->sin_addr.s_addr, ((struct sockaddr_in *)&socket->dst_addr)->sin_addr.s_addr, ((struct sockaddr_in *)&socket->src_addr)->sin_port, ((struct sockaddr_in *)&socket->dst_addr)->sin_port, socket->seq_num, 0x00000000, FIN, BUF_SIZE - socket->rb.size, NULL);

			socket->seq_num += 1;
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

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int fd, void *buf, size_t count)
{
	std::array<int, 2> fd_to_pid = {{fd, pid}};
	auto socket_iter = fd_to_socket.find(fd_to_pid);
	if(socket_iter == fd_to_socket.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	struct sock_info *socket = &socket_iter->second;
	if(socket->pid != pid)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	if(socket->connection_state != CONNECTED || socket->close_state != UNCLOSED)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	if(socket->rb.cont_size > 0)
	{
		size_t read_count = rb_read(&socket->rb, buf, count);
		socket->rb.start = (socket->rb.start + read_count) % (BUF_SIZE + 1);
		socket->rb.size -= read_count;

		this->returnSystemCall(syscallUUID, read_count);
		return;
	}
	else
	{
		socket->read_called = true;
		socket->read_buf = buf;
		socket->read_count = count;

		socket->uuid = syscallUUID;
		return;
	}
}

void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int fd, const void *buf, size_t count)
{
	std::array<int, 2> fd_to_pid = {{fd, pid}};
	auto socket_iter = fd_to_socket.find(fd_to_pid);
	if(socket_iter == fd_to_socket.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	struct sock_info *socket = &socket_iter->second;
	if(socket->pid != pid)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	if(socket->connection_state != CONNECTED || socket->close_state != UNCLOSED)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	if(count <= BUF_SIZE - socket->wb.size)
	{
		size_t write_count = wb_write(&socket->wb, (void *)buf, count);

		this->returnSystemCall(syscallUUID, write_count);

		if(socket->rwnd >= socket->wmgr.size)
		{
			uint32_t seg_len;
			while(socket->wb.size > socket->wmgr.size)
			{
				seg_len = socket->wb.size - socket->wmgr.size >= MSS ? MSS : socket->wb.size - socket->wmgr.size;

				struct write_info wi;
				wi.start = socket->wmgr.end;
				wi.end = (wi.start + seg_len) % (BUF_SIZE + 1);
				wi.size = seg_len;
				wi.seq_num = socket->seq_num;

				uint8_t payload[MSS];
				size_t read_count = wb_read(&socket->wb, wi.start, payload, wi.size);

				send_packet(20 + 20 + read_count, ((struct sockaddr_in *)&socket->src_addr)->sin_addr.s_addr, ((struct sockaddr_in *)&socket->dst_addr)->sin_addr.s_addr, ((struct sockaddr_in *)&socket->src_addr)->sin_port, ((struct sockaddr_in *)&socket->dst_addr)->sin_port, socket->seq_num, socket->ack_num, ACK, BUF_SIZE - socket->rb.size, payload);

				if(socket->wmgr.write_infos.empty())
				{
					struct timer_payload *timer = new struct timer_payload;
					timer->type = PAYLOAD_PACKET;
					timer->socket = socket;
					socket->retransmit_timer = timer;

					timer->uuid = addTimer(timer, TimeUtil::makeTime(100, TimeUtil::MSEC));
				}

				socket->wmgr.write_infos.push_back(wi);
				socket->wmgr.end = wi.end;
				socket->wmgr.size += wi.size;
				socket->seq_num += wi.size;
			}
		}
	}
	else
	{
		socket->write_called = true;
		socket->write_buf = (void *)buf;
		socket->write_count = count;

		socket->uuid = syscallUUID;
	}
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd,
		struct sockaddr *addr, socklen_t addrlen)
{
	std::array<int, 2> fd_to_pid = {{sockfd, pid}};
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

	send_packet(20 + 20, ((struct sockaddr_in *)&c_socket->src_addr)->sin_addr.s_addr, ((struct sockaddr_in *)&c_socket->dst_addr)->sin_addr.s_addr, ((struct sockaddr_in *)&c_socket->src_addr)->sin_port, ((struct sockaddr_in *)&c_socket->dst_addr)->sin_port, c_socket->seq_num, 0x00000000, SYN, BUF_SIZE - c_socket->rb.size, NULL);

	c_socket->seq_num += 1;
	c_socket->tcp_state = TCP_SYN_SENT;

	c_socket->uuid = syscallUUID;
	return;
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog)
{
	std::array<int, 2> fd_to_pid = {{sockfd, pid}};
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
	std::array<int, 2> fd_to_pid = {{sockfd, pid}};
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
		if(connection->tcp_state == TCP_ESTABLISHED || connection->tcp_state == TCP_CLOSE_WAIT)
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

		std::array<int, 2> fd_to_pid = {{fd, pid}};

		if(fd_to_socket.find(fd_to_pid) != fd_to_socket.end())
		{
			this->returnSystemCall(syscallUUID, -1);
			return;
		}

		struct sock_info s_socket;
		static struct write_buffer empty_wb;		
		static struct write_manager empty_wmgr;
		s_socket.uuid = 0;
		s_socket.pid = pid;
		s_socket.src_addr = connection->src_addr;
		s_socket.dst_addr = connection->dst_addr;
		s_socket.bound_state = BOUND;
		s_socket.connection_state = CONNECTED;
		s_socket.close_state = UNCLOSED;
		s_socket.tcp_state = connection->tcp_state;
		s_socket.backlog = 0;
		s_socket.seq_num = connection->seq_num;
		s_socket.ack_num = connection->ack_num;
		s_socket.accept_called = false;
		s_socket.accept_addr = NULL;
		s_socket.accept_addrlen = NULL;
		s_socket.rmgr = connection->rmgr;
		s_socket.rb = connection->rb;
		s_socket.read_called = false;
		s_socket.read_buf = NULL;
		s_socket.read_count = 0;
		s_socket.wmgr = empty_wmgr;
		s_socket.wb = empty_wb;
		s_socket.write_called = false;
		s_socket.write_buf = NULL;
		s_socket.write_count = 0;
		s_socket.smallest_unacked = s_socket.seq_num;
		s_socket.rwnd = BUF_SIZE;
		s_socket.dup_ack_count = 0;
		s_socket.retransmit_timer = NULL;

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
	std::array<int, 2> fd_to_pid = {{sockfd, pid}};
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
	std::array<int, 2> fd_to_pid = {{sockfd, pid}};
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
	std::array<int, 2> fd_to_pid = {{sockfd, pid}};
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

void TCPAssignment::send_packet(uint16_t total_len, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint32_t seq_num, uint32_t ack_num, uint8_t flags, uint16_t rwnd, void *payload)
{
	uint16_t packet_totallen = htons(total_len);
	uint32_t packet_src_ip = src_ip;
	uint32_t packet_dst_ip = dst_ip;
	uint16_t packet_src_port = src_port;
	uint16_t packet_dst_port = dst_port;
	uint32_t packet_seq_num = htonl(seq_num);
	uint32_t packet_ack_num = htonl(ack_num);
	uint8_t packet_headerlen = (uint8_t)0x50;
	uint8_t packet_flags = flags;
	uint16_t packet_rwnd = htons(rwnd);
	uint16_t packet_checksum = (uint16_t)0x0000;
	uint16_t packet_pointer = (uint16_t)0x0000;

	Packet *pkt = this->allocatePacket(14 + total_len);
	pkt->writeData(14 + 2, &packet_totallen, 2);
	pkt->writeData(14 + 12, &packet_src_ip, 4);
	pkt->writeData(14 + 16, &packet_dst_ip, 4);
	pkt->writeData(14 + 20 + 0, &packet_src_port, 2);
	pkt->writeData(14 + 20 + 2, &packet_dst_port, 2);
	pkt->writeData(14 + 20 + 4, &packet_seq_num, 4);
	pkt->writeData(14 + 20 + 8, &packet_ack_num, 4);
	pkt->writeData(14 + 20 + 12, &packet_headerlen, 1);
	pkt->writeData(14 + 20 + 13, &packet_flags, 1);
	pkt->writeData(14 + 20 + 14, &packet_rwnd, 2);
	pkt->writeData(14 + 20 + 16, &packet_checksum, 2);
	pkt->writeData(14 + 20 + 18, &packet_pointer, 2);
	pkt->writeData(14 + 20 + 20, payload, total_len - 20 - 20);

	uint32_t source, dest;
	uint8_t tcp_seg[total_len - 20];
	pkt->readData(14 + 12, &source, sizeof(source));
	pkt->readData(14 + 16, &dest, sizeof(dest));
	pkt->readData(14 + 20, tcp_seg, sizeof(tcp_seg));

	packet_checksum = htons(0xFFFF - NetworkUtil::tcp_sum(source, dest, tcp_seg, sizeof(tcp_seg)));
	pkt->writeData(14 + 20 + 16, &packet_checksum, 2);

	this->sendPacket("IPv4", pkt);
}

size_t TCPAssignment::rb_read(struct read_buffer *rb, void *buf, size_t count)
{
	size_t read_count = rb->cont_size >= count ? count : rb->cont_size;
	if(rb->start + read_count > BUF_SIZE)
	{
		memcpy(buf, rb->buffer + rb->start, BUF_SIZE - rb->start);
		memcpy((uint8_t *)buf + (BUF_SIZE - rb->start), rb->buffer, read_count - (BUF_SIZE - rb->start));
	}
	else
		memcpy(buf, rb->buffer + rb->start, read_count);
	return read_count;
}

size_t TCPAssignment::rb_write(struct read_buffer *rb, size_t pos, void *buf, size_t count)
{
	if(pos + count > BUF_SIZE)
	{
		memcpy(rb->buffer + pos, buf, BUF_SIZE - pos);
		memcpy(rb->buffer, (uint8_t *)buf + (BUF_SIZE - pos), count - (BUF_SIZE - pos));
		rb->end = rb->end >= count - (BUF_SIZE - pos) ? rb->end : count - (BUF_SIZE - pos);
		rb->size = rb->end + BUF_SIZE - rb->start;
	}
	else
	{
		memcpy(rb->buffer + pos, buf, count);
		rb->end = rb->end >= pos + count ? rb->end : pos + count;
		rb->size = rb->end - rb->start;
	}
	return count;
}

size_t TCPAssignment::wb_read(struct write_buffer *wb, size_t pos, void *buf, size_t count)
{
	size_t read_count = wb->size >= count ? count : wb->size;
	if(pos + read_count > BUF_SIZE)
	{
		memcpy(buf, wb->buffer + pos, BUF_SIZE - pos);
		memcpy((uint8_t *)buf + (BUF_SIZE - pos), wb->buffer, read_count - (BUF_SIZE - pos));
	}
	else
		memcpy(buf, wb->buffer + pos, read_count);
	return read_count;
}


size_t TCPAssignment::wb_write(struct write_buffer *wb, void *buf, size_t count)
{
	if(wb->end + count > BUF_SIZE)
	{
		memcpy(wb->buffer + wb->end, buf, BUF_SIZE - wb->end);
		memcpy(wb->buffer, (uint8_t *)buf + (BUF_SIZE - wb->end), count - (BUF_SIZE - wb->end));
		wb->end = count - (BUF_SIZE - wb->end);
	}
	else
	{
		memcpy(wb->buffer + wb->end, buf, count);
		wb->end += count;
	}
	wb->size += count;
	return count;
}


bool asc_seq(const struct read_info& l, const struct read_info& r)
{
   return l.seq_num < r.seq_num;
}

}

