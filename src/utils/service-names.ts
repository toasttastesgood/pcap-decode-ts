/**
 * A map of common port numbers to service names.
 * The key is a string in the format "port/protocol".
 */
const serviceNameMap: Record<string, string> = {
  '20/tcp': 'FTP-Data',
  '21/tcp': 'FTP-Control',
  '22/tcp': 'SSH',
  '23/tcp': 'Telnet',
  '25/tcp': 'SMTP',
  '53/tcp': 'DNS',
  '53/udp': 'DNS',
  '67/udp': 'DHCP Server', // BOOTP Server
  '68/udp': 'DHCP Client', // BOOTP Client
  '69/udp': 'TFTP',
  '80/tcp': 'HTTP',
  '110/tcp': 'POP3',
  '123/udp': 'NTP',
  '137/udp': 'NetBIOS-NS',
  '138/udp': 'NetBIOS-DGM',
  '139/tcp': 'NetBIOS-SSN',
  '143/tcp': 'IMAP',
  '161/udp': 'SNMP',
  '162/udp': 'SNMPTRAP',
  '194/tcp': 'IRC',
  '389/tcp': 'LDAP',
  '443/tcp': 'HTTPS',
  '445/tcp': 'Microsoft-DS', // SMB
  '514/udp': 'Syslog',
  '520/udp': 'RIP',
  '546/udp': 'DHCPv6-Client',
  '547/udp': 'DHCPv6-Server',
  '636/tcp': 'LDAPS',
  '993/tcp': 'IMAPS',
  '995/tcp': 'POP3S',
  '1080/tcp': 'SOCKS',
  '1433/tcp': 'MSSQL-Server',
  '1521/tcp': 'Oracle',
  '3306/tcp': 'MySQL',
  '3389/tcp': 'RDP', // MS-WBT-Server
  '5060/tcp': 'SIP',
  '5060/udp': 'SIP',
  '5061/tcp': 'SIPS',
  '5432/tcp': 'PostgreSQL',
  '5900/tcp': 'VNC',
  '6379/tcp': 'Redis',
  '8080/tcp': 'HTTP-Proxy',
  '27017/tcp': 'MongoDB',
};

/**
 * Gets the common service name for a given port number and protocol.
 *
 * @param port - The port number.
 * @param protocol - The protocol, either 'tcp' or 'udp'.
 * @returns The common service name as a string if found, otherwise null.
 */
export function getServiceName(port: number, protocol: 'tcp' | 'udp'): string | null {
  if (typeof port !== 'number' || port < 0 || port > 65535) {
    return null; // Invalid port number
  }
  const key = `${port}/${protocol.toLowerCase()}`;
  return serviceNameMap[key] || null;
}
