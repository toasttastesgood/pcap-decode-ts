import { describe, it, expect } from 'vitest';
import { getServiceName } from '../../utils/service-names';

describe('getServiceName', () => {
  it('should return "HTTP" for port 80 and protocol "tcp"', () => {
    expect(getServiceName(80, 'tcp')).toBe('HTTP');
  });

  it('should return "HTTPS" for port 443 and protocol "tcp"', () => {
    expect(getServiceName(443, 'tcp')).toBe('HTTPS');
  });

  it('should return "DNS" for port 53 and protocol "udp"', () => {
    expect(getServiceName(53, 'udp')).toBe('DNS');
  });

  it('should return "DNS" for port 53 and protocol "tcp"', () => {
    expect(getServiceName(53, 'tcp')).toBe('DNS');
  });

  it('should return "FTP-Control" for port 21 and protocol "tcp"', () => {
    expect(getServiceName(21, 'tcp')).toBe('FTP-Control');
  });

  it('should return "SSH" for port 22 and protocol "tcp"', () => {
    expect(getServiceName(22, 'tcp')).toBe('SSH');
  });

  it('should return "Telnet" for port 23 and protocol "tcp"', () => {
    expect(getServiceName(23, 'tcp')).toBe('Telnet');
  });

  it('should return "SMTP" for port 25 and protocol "tcp"', () => {
    expect(getServiceName(25, 'tcp')).toBe('SMTP');
  });

  it('should return "DHCP Server" for port 67 and protocol "udp"', () => {
    expect(getServiceName(67, 'udp')).toBe('DHCP Server');
  });

  it('should return "DHCP Client" for port 68 and protocol "udp"', () => {
    expect(getServiceName(68, 'udp')).toBe('DHCP Client');
  });

  it('should return "TFTP" for port 69 and protocol "udp"', () => {
    expect(getServiceName(69, 'udp')).toBe('TFTP');
  });

  it('should return "NTP" for port 123 and protocol "udp"', () => {
    expect(getServiceName(123, 'udp')).toBe('NTP');
  });

  it('should return "NetBIOS-NS" for port 137 and protocol "udp"', () => {
    expect(getServiceName(137, 'udp')).toBe('NetBIOS-NS');
  });

  it('should return "IMAP" for port 143 and protocol "tcp"', () => {
    expect(getServiceName(143, 'tcp')).toBe('IMAP');
  });

  it('should return "SNMP" for port 161 and protocol "udp"', () => {
    expect(getServiceName(161, 'udp')).toBe('SNMP');
  });

  it('should return null for a port not in the map (e.g., port 9999, tcp)', () => {
    expect(getServiceName(9999, 'tcp')).toBeNull();
  });

  it('should return null for a port not in the map (e.g., port 1, udp)', () => {
    expect(getServiceName(1, 'udp')).toBeNull();
  });

  it('should be case-insensitive for protocol (e.g., "TCP" should work)', () => {
    // @ts-expect-error Testing case-insensitivity for protocol
    expect(getServiceName(80, 'TCP')).toBe('HTTP');
  });

  it('should return null for an invalid port number (negative)', () => {
    expect(getServiceName(-1, 'tcp')).toBeNull();
  });

  it('should return null for an invalid port number (too large)', () => {
    expect(getServiceName(65536, 'tcp')).toBeNull();
  });

  it('should return null for an invalid port number (string, though TS prevents this)', () => {
    // @ts-expect-error Testing invalid port type
    expect(getServiceName('abc', 'tcp')).toBeNull();
  });

  it('should return null for an invalid protocol (though TS prevents this)', () => {
    // @ts-expect-error Testing invalid protocol type
    expect(getServiceName(80, 'ftp')).toBeNull();
  });
});
