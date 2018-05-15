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
#include <array>

namespace E
{

	#define BUF_SIZE 51200
	#define MSS 512

	enum Bound_State {UNBOUND, BOUND};
	enum Connection_State {UNCONNECTED, CONNECTED};
	enum Close_State {UNCLOSED, CLOSED};
	enum TCP_State {TCP_CLOSED, TCP_LISTEN, TCP_SYN_SENT, TCP_SYN_RCVD, TCP_ESTABLISHED, TCP_CLOSE_WAIT, TCP_LAST_ACK, TCP_FIN_WAIT_1, TCP_FIN_WAIT_2, TCP_CLOSING, TCP_TIME_WAIT};
	enum TCP_Flags {SYN = 0x02, SYNACK = 0x12, ACK = 0x10, FIN = 0x01};
	enum Payload_Type {PAYLOAD_SOCKET, PAYLOAD_CONNECTION, PAYLOAD_PACKET};

	struct timer_payload
	{
		UUID uuid;
		enum Payload_Type type;
		struct sock_info *socket;
		struct connection *connection;
	};
	
	struct read_info
	{
		size_t start;
		size_t end;
		size_t size;
		uint32_t seq_num;
	};

	struct write_info
	{
		size_t start;
		size_t end;
		size_t size;
		uint32_t seq_num;
	};

	struct read_manager
	{
		std::list<struct read_info> read_infos;
		size_t start;
		size_t end;
		size_t size;
	};

	struct write_manager
	{
		std::list<struct write_info> write_infos;
		size_t start;
		size_t end;
		size_t size;
	};

	struct read_buffer
	{
		uint8_t buffer[BUF_SIZE + 1];
		size_t start;
		size_t cont_end;
		size_t end;
		size_t cont_size;
		size_t size;
	};

	struct write_buffer
	{
		uint8_t buffer[BUF_SIZE + 1];
		size_t start;
		size_t end;
		size_t size;
	};

	struct connection
	{
		sockaddr src_addr;
		sockaddr dst_addr;
		enum TCP_State tcp_state;
		uint32_t seq_num;
		uint32_t ack_num;
		struct read_manager rmgr;
		struct read_buffer rb;
	};

	struct sock_info
	{
		UUID uuid;
		int pid;
		sockaddr src_addr;
		sockaddr dst_addr;
		enum Bound_State bound_state;
		enum Connection_State connection_state;
		enum Close_State close_state;
		enum TCP_State tcp_state;
		int backlog;
		uint32_t seq_num;
		uint32_t ack_num;
		std::list<struct connection> connections;

		bool close_called;

		bool accept_called;
		sockaddr *accept_addr;
		socklen_t *accept_addrlen;

		struct read_manager rmgr;
		struct read_buffer rb;
		bool read_called;
		void *read_buf;
		size_t read_count;

		struct write_manager wmgr;
		struct write_buffer wb;
		bool write_called;
		void *write_buf;
		size_t write_count;

		uint32_t smallest_unacked;
		uint16_t rwnd;

		int dup_ack_count;
		struct timer_payload *retransmit_timer;
	};

	bool asc_seq(const struct read_info& l, const struct read_info& r);

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
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

	void syscall_read(UUID syscallUUID, int pid, int fd, void *buf, size_t count);

	void syscall_write(UUID syscallUUID, int pid, int fd, const void *buf, size_t count);

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

	void send_packet(uint16_t total_len, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint32_t seq_num, uint32_t ack_num, uint8_t flags, uint16_t rwnd, void *payload);

	size_t rb_read(struct read_buffer *rb, void *buf, size_t count);
	size_t rb_write(struct read_buffer *rb, size_t pos, void *buf, size_t count);
	size_t wb_read(struct write_buffer *wb, size_t pos, void *buf, size_t count);
	size_t wb_write(struct write_buffer *wb, void *buf, size_t count);
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
