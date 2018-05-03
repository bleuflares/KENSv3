/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>


#include <E/E_TimerModule.hpp>

namespace E
{

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
	enum Bound_State {UNBOUND, BOUND};
	enum Connection_State {UNCONNECTED, CONNECTED};
	enum TCP_State {TCP_CLOSED, TCP_LISTEN, TCP_SYN_SENT, TCP_SYN_RCVD, TCP_ESTABLISHED, TCP_CLOSE_WAIT, TCP_LAST_ACK, TCP_FIN_WAIT_1, TCP_FIN_WAIT_2, TCP_CLOSING, TCP_TIME_WAIT};
	enum TCP_Flags {SYN = 0x02, SYNACK = 0x12, ACK = 0x10, FIN = 0x01};
	enum Payload_Type {SOCKET, CONNECTION};

	
	struct connection
	{
		sockaddr src_addr;
		sockaddr dst_addr;
		enum Connection_State connection_state;
		enum TCP_State tcp_state;
		uint32_t seq_num;
		uint32_t ack_num;
	};

	struct sock_info
	{
		UUID uuid;
		int pid;
		sockaddr src_addr;
		sockaddr dst_addr;
		enum Bound_State bound_state;
		enum Connection_State connection_state;
		enum TCP_State tcp_state;
		int backlog;
		uint32_t seq_num;
		uint32_t ack_num;
		std::list<struct connection> connections;
		bool accept_called;
		sockaddr *accept_addr;
		socklen_t *accept_addrlen;
	};

	struct timer_payload
	{
		UUID uuid;
		enum Payload_Type type;
		struct sock_info *socket;
		struct connection *connection;
	};

	std::map<std::array<int, 2>, struct sock_info> fd_to_socket;

private:
	virtual void timerCallback(void* payload) final;

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();

	void syscall_socket(UUID syscallUUID, int pid, int domain, int type__unused);

	void syscall_close(UUID syscallUUID, int pid, int fd);
	/*
	void TCPAssignment::syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);

	void TCPAssignment::syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
	*/
	void syscall_connect(UUID syscallUUID, int pid, int sockfd,
		struct sockaddr *addr, socklen_t addrlen);

	void syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog);

	void syscall_accept(UUID syscallUUID, int pid, int sockfd,
		struct sockaddr *addr,
		socklen_t *addrlen);

	void syscall_bind(UUID syscallUUID, int pid, int sockfd,
		struct sockaddr *addr,
		socklen_t addrlen);

	void syscall_getsockname(UUID syscallUUID, int pid, int sockfd,
		struct sockaddr *addr,
		socklen_t *addrlen);

	void syscall_getpeername(UUID syscallUUID, int pid, int sockfd,
		struct sockaddr *addr,
		socklen_t *addrlen);

protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
