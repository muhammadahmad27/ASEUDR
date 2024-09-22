from rich.console import Console
import argparse
from ipaddress import IPv4Address, AddressValueError
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
import random


class ASEUDR:
    def __init__(self):
        self.console = Console()
        self.args = self.initialize_argparse()

        self.dns_resolvers_file_path = self.args.dns_resolvers_file_path
        self.dns_resolvers = []

        self.domains_file_path = self.args.domains_file_path
        self.domains = []

        self.wordlist_file_path = self.args.wordlist_file_path
        self.wordlist = []

        self.trusted_dns_resolvers = [
            '208.67.222.220',
            '8.8.8.8',
            '9.9.9.9',
            '207.177.68.4',
            '64.6.64.6',
            '185.228.169.9',
            '66.206.166.2',
            '198.55.49.149',
            '195.46.39.39',
            '5.11.11.5',
            '87.213.100.113',
            '80.67.169.40',
            '84.236.142.130',
            '83.137.41.9',
            '37.209.219.30',
            '194.172.160.4',
            '148.235.82.66',
            '200.221.11.101',
            '211.25.206.147',
            '1.1.1.1',
            '61.8.0.113',
            '122.56.107.86',
            '139.59.219.245',
            '164.124.101.2',
            '202.46.34.75',
            '31.7.37.37',
            '115.178.96.2',
            '209.150.154.1',
            '185.228.168.9',
            '103.157.237.34'
        ]
        self.trusted_dns_resolver = '8.8.8.8'
        self.baseline_root_domain = self.args.baseline_root_domain
        self.baseline_root_domain_ip4_address = []
        self.nxdomain = self.args.nxdomain

        self.valid_dns_resolvers = []

        self.output_dns_resolvers_file_path = self.args.output_dns_resolvers
        self.output_domains_file_path = self.args.output_domains

        self.valid_domains = []

    def initialize_argparse(self):
        parser = argparse.ArgumentParser(description='Active Subdomains Enumeration Using DNS Resolvers.',
                                         epilog='')

        parser.add_argument('dns_resolvers_file_path',
                            help='Specify the file path containing the DNS resolvers.')

        parser.add_argument('-dfp', '--domains_file_path',
                            help='Specify the file path containing the domains.',
                            default=None)
        parser.add_argument('-brd', '--baseline_root_domain',
                            help='Specify the baseline root domain (non-geolocated) to validate the DNS resolvers (default: bbc.com).',
                            default='bbc.com')
        parser.add_argument('-nxd', '--nxdomain',
                            help='Specify the root domain to validate the DNS resolvers using the NXDOMAIN validation (default: google.com).',
                            default='google.com')
        parser.add_argument('-dnv', '--disable_nxdomain_validation',
                            help='Disable NXDOMAIN validation (default: False).',
                            action='store_true')
        parser.add_argument('-t', '--threads',
                            help='Specify the number of threads to use (default: 1).',
                            default=1,
                            type=int)
        parser.add_argument('-or', '--output_dns_resolvers',
                            help='Specify the file path to save DNS resolvers (default: dns_resolvers.txt).',
                            default='dns_resolvers.txt')
        parser.add_argument('-od', '--output_domains',
                            help='Specify the file path to save domains (default: valid_domains.txt).',
                            default='valid_domains.txt')
        parser.add_argument('-edv', '--enable_dns_validator',
                            help='Enable DNS validator (default: False).',
                            action='store_true')
        parser.add_argument('-m', '--mode',
                            help='Specify the desired mood (default: resolver).',
                            default='resolver',
                            choices=['resolver', 'brute-force'])
        parser.add_argument('-w', '--wordlist_file_path',
                            help='Specify the file path containing the subdomains.',
                            default=None)
        parser.add_argument('-d', '--domain',
                            help='Please input the domain.',
                            default=None)

        args = parser.parse_args()

        if args.disable_nxdomain_validation and (args.nxdomain != 'google.com'):
            self.console.print('\n[bold red][-] --nxdomain can not be used with --disable_nxdomain_validation.[/bold red]')
            exit()

        if args.mode == 'brute-force' and (not args.wordlist_file_path or not args.domain):
            self.console.print('\n[bold red][-] brute-force mode can not be used without --wordlist_file_path and --domain.[/bold red]')
            exit()

        if args.mode == 'resolver' and (args.wordlist_file_path or args.domain):
            self.console.print('\n[bold red][-] --wordlist_file_path or --domain can be used with brute-force mode.[/bold red]')
            exit()

        if args.mode == 'resolver' and not args.domains_file_path:
            self.console.print('\n[bold red][-] --mode resolver and --domains_file_path should be used together.[/bold red]')
            exit()

        return args

    @staticmethod
    def is_valid_ipv4(ip):
        try:
            IPv4Address(ip)
            return True
        except AddressValueError:
            return False

    def read_dns_resolvers_file(self):
        with open(self.dns_resolvers_file_path) as file:
            i = 0
            for line in file.readlines():
                if i == 10:
                    break
                if self.is_valid_ipv4(line.strip()):
                    self.dns_resolvers.append(line.strip())
                i += 1

    @staticmethod
    def resolve_domain(domain, dns_servers):
        resolver = dns.resolver.Resolver(configure=False)

        resolver.nameservers = dns_servers

        try:
            answer = resolver.resolve(domain, 'A')
            return answer
        except dns.resolver.NoAnswer:
            return 'NoAnswer'
        except dns.resolver.NXDOMAIN:
            return 'NXDOMAIN'
        except dns.resolver.Timeout:
            return 'Timeout'
        except Exception:
            return 'Exception'

    def is_baseline_root_domain_non_geolocated(self):
        baseline_root_domain_ip4_address = []
        if self.args.baseline_root_domain == 'bbc.com':
            answer = self.resolve_domain(self.baseline_root_domain, [self.trusted_dns_resolver])
            for ip in answer:
                self.baseline_root_domain_ip4_address.append(str(ip))
            return
        else:
            self.console.print('\n[bold yellow][*] Starting verification: checking if the baseline root domain is non-geolocated.[/bold yellow]')
            for trusted_dns_resolver in self.trusted_dns_resolvers:
                answer = self.resolve_domain(self.baseline_root_domain, [trusted_dns_resolver])
                if answer == 'NoAnswer' or answer == 'NXDOMAIN' or answer == 'Timeout' or answer == 'Exception':
                    self.console.print('\n[bold red][-] {} raised {}.[/bold red]'.format(trusted_dns_resolver, answer))
                    continue
                for ip in answer:
                    baseline_root_domain_ip4_address.append(str(ip))
                self.console.print('\n', end='')
                self.console.print('[bold blue][*] {} -> {}[/bold blue]'.format(trusted_dns_resolver, ', '.join(baseline_root_domain_ip4_address)))
                if not self.baseline_root_domain_ip4_address:
                    self.baseline_root_domain_ip4_address = baseline_root_domain_ip4_address
                else:
                    if sorted(baseline_root_domain_ip4_address) != sorted(self.baseline_root_domain_ip4_address):
                        self.console.print('\n[bold red][-] {} is geolocated.[/bold red]'.format(self.baseline_root_domain))
                        exit()
                baseline_root_domain_ip4_address = []

        self.console.print('\n[bold green][+] {} is non-geolocated.[/bold green]'.format(self.baseline_root_domain))

    def same_ip_address_validator(self):
        self.console.print('\n[bold yellow][*] Starting verification: checking if the DNS resolver and trusted DNS resolver return the same IP address.[/bold yellow]')
        for dns_resolver in self.dns_resolvers:
            answer = self.resolve_domain(self.baseline_root_domain, [dns_resolver])
            ip_addresses = []
            if answer == 'NoAnswer' or answer == 'NXDOMAIN' or answer == 'Timeout' or answer == 'Exception':
                self.console.print('\n[bold red][-] {} raised {}.[/bold red]'.format(dns_resolver, answer))
                continue
            for ip in answer:
                ip_addresses.append(str(ip))
            if sorted(ip_addresses) == sorted(self.baseline_root_domain_ip4_address):
                self.valid_dns_resolvers.append(dns_resolver)
                self.console.print('\n[bold green][+] {} is valid.[/bold green]'.format(dns_resolver))

    def nxdomain_validator(self):
        self.console.print('\n[bold yellow][*] Starting verification: checking if the DNS resolver returns NXDOMAIN for non-existent subdomains of known target root domains.[/bold yellow]')
        for dns_resolver in self.valid_dns_resolvers:
            answer = self.resolve_domain('nxdomainnxdomain.' + self.nxdomain, [dns_resolver])
            if answer != 'NXDOMAIN':
                self.valid_dns_resolvers.remove(dns_resolver)
                self.console.print('\n[bold red][-] {} is removed.[/bold red]'.format(dns_resolver))
            else:
                self.console.print('\n[bold green][+] {} is valid.[/bold green]'.format(dns_resolver))

    def save_valid_dns_resolvers(self):
        with open(self.output_dns_resolvers_file_path, 'w') as file:
            file.write('\n'.join(self.valid_dns_resolvers))
        self.console.print('\n[bold green][+] Valid DNS resolvers saved in {}.[/bold green]'.format(self.output_dns_resolvers_file_path))

    def read_domains_file_path(self):
        with open(self.domains_file_path) as file:
            for line in file.readlines():
                self.domains.append(line.strip())

    def updated_resolve_domain_func(self, domain, dns_resolvers):
        while True:
            resolver_ip_address = random.choice(dns_resolvers)

            resolver = dns.resolver.Resolver(configure=False)

            resolver.nameservers = [resolver_ip_address]

            try:
                answer = resolver.resolve(domain, 'A')
                return answer, resolver_ip_address
            except dns.resolver.NoAnswer:
                return 'NoAnswer', resolver_ip_address
            except dns.resolver.NXDOMAIN:
                return 'NXDOMAIN', resolver_ip_address
            except dns.resolver.Timeout:
                self.console.print('\n[bold red][-] {} -> {} raised Timeout.[/bold red]'.format(resolver_ip_address, domain))
                continue
            except Exception:
                return 'Exception', resolver_ip_address

    def resolve_subdomains(self):
        self.console.print('\n[bold yellow][*] Initiating subdomain enumeration...[/bold yellow]')
        dns_resolvers = self.valid_dns_resolvers if self.args.enable_dns_validator else self.dns_resolvers
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            if self.args.mode == 'resolver':
                futures = {executor.submit(self.updated_resolve_domain_func, domain, dns_resolvers): domain for domain in self.domains}
            else:
                futures = {executor.submit(self.updated_resolve_domain_func, (subdomain + '.' + self.args.domain), dns_resolvers): (subdomain + '.' + self.args.domain) for subdomain in self.wordlist}

            for future in as_completed(futures):
                domain = futures[future]
                answer, resolver_ip_address = future.result()
                if answer == 'NoAnswer' or answer == 'NXDOMAIN' or answer == 'Timeout' or answer == 'Exception':
                    self.console.print('\n[bold red][-] {} -> {} raised {}.[/bold red]'.format(resolver_ip_address, domain, answer))
                    continue
                for ip in answer:
                    self.console.print('\n[bold blue][*] {} -> {} -> {}.[/bold blue]'.format(resolver_ip_address, domain, str(ip)))
                    self.valid_domains.append(domain)

    def printing_and_saving_valid_domains(self):
        self.console.print('\n[bold green][+] {} valid subdomains found.[/bold green]'.format(len(self.valid_domains)))
        self.console.print('\n'.join([f'[bold green][*][/bold green] [bold italic green]{domain}[/bold italic green]' for domain in self.valid_domains]))

        with open(self.output_domains_file_path, 'w') as file:
            file.write('\n'.join(self.valid_domains))
        self.console.print('\n[bold green][+] Valid domains saved in {}.[/bold green]'.format(self.output_domains_file_path))

    def read_wordlist_file_path(self):
        with open(self.wordlist_file_path) as file:
            for line in file.readlines():
                self.wordlist.append(line.strip())

    def start(self):
        self.read_dns_resolvers_file()

        if self.args.enable_dns_validator:
            self.is_baseline_root_domain_non_geolocated()
            self.same_ip_address_validator()

            if not self.args.disable_nxdomain_validation:
                self.nxdomain_validator()
            else:
                self.console.print('\n[bold blue][*] NXDOMAIN validation skipped.[/bold blue]')

            self.save_valid_dns_resolvers()

        if self.args.mode == 'brute-force':
            self.read_wordlist_file_path()
        else:
            self.read_domains_file_path()

        self.resolve_subdomains()
        self.printing_and_saving_valid_domains()


aseudr = ASEUDR()
aseudr.start()
