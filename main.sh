#!/bin/bash
# Detecta se os usuários Debian estão rodando o script "sh" inves de bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo 'Este instalador precisa ser executado em "bash", não em "sh".'
	exit
fi

# Descarta o stdin. Necessário ao executar a partir de uma linha que inclui uma nova linha
read -N 999999 -t 0.001

# Detecta OpenVZ 6
if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
	echo "O sistema está rodando em um kernel antigo, o qual é incompatível com este instalador."
	exit
fi

# Detecta Sistema Operacional
# $os_version não estão sempre em uso, mas são mantidas aqui por conveniência
if grep -qs "ubuntu" /etc/os-release; then
	os="ubuntu"
	os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
	group_name="nogroup"
elif [[ -e /etc/debian_version ]]; then
	os="debian"
	os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
	group_name="nogroup"
elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
	os="centos"
	os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
	group_name="nobody"
elif [[ -e /etc/fedora-release ]]; then
	os="fedora"
	os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
	group_name="nobody"
else
	echo "Este instalador parece estar sendo executado em uma distribuição não suportada.
As distribuições suportadas são Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS e Fedora."
	exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
	echo "Ubuntu 18.04 ou superior é necessário para rodar este instalador.
Esta versão do Ubuntu é muito antiga e não é mais suportada."
	exit
fi

if [[ "$os" == "debian" && "$os_version" -lt 9 ]]; then
	echo "Debian 9 ou superior é necessário para rodar este instalador.
Esta versão do Debian é muito antiga e não é mais suportada."
	exit
fi

if [[ "$os" == "centos" && "$os_version" -lt 7 ]]; then
	echo "CentOS 7 ou superior é necessário para rodar este instalador.
Esta versão do CentOS é muito antiga e não é mais suportada.."
	exit
fi

# Detecta os ambients onde $PATH não inclui os diretórios sbin
if ! grep -q sbin <<< "$PATH"; then
	echo '$PATH não inclui sbin. Tente usar "su -" invés de "su".'
	exit
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "Este instalador precisa ser executado com privilégios de Super Usuário."
	exit
fi

if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
	echo "Este sistema não tem o dispositivo TUN disponível.
TUN precisa estar ativo antes de rodar este instalador."
	exit
fi

new_client () {
	# Gera clientes customizados client.ovpn
	{
	cat /etc/openvpn/server/client-common.txt
	echo "<ca>"
	cat /etc/openvpn/server/easy-rsa/pki/ca.crt
	echo "</ca>"
	echo "<cert>"
	sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt
	echo "</cert>"
	echo "<key>"
	cat /etc/openvpn/server/easy-rsa/pki/private/"$client".key
	echo "</key>"
	echo "<tls-crypt>"
	sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/tc.key
	echo "</tls-crypt>"
	} > ~/"$client".ovpn
}

if [[ ! -e /etc/openvpn/server/server.conf ]]; then
	# Detecta algumas configurações mínimas do Debian, onde nem o wget nem curl estão instalados
	if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
		echo "É necessário ter o pacote Wget instalado para rodar este instalador"
		read -n1 -r -p "Aperte qualquer tecla para instalar Wget de seus respositórios e continuar com a instalação..."
		apt-get update
		apt-get install -y wget
	fi
	clear
	echo 'Bem-vindo ao instalador de VPN Road Warrior!'
	# Se o sistema tiver um único IPv4 será selecionado automaticamente. Caso contrário, será perguntado ao Usuário.
	if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
		echo
		echo "Qual IPv4 deve ser usado?"
		ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
		read -p "Endereço IPv4 [1]: " ip_number
		until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
			echo "$ip_number: Entrada Inválida."
			read -p "Endereço IPv4 [1]: " ip_number
		done
		[[ -z "$ip_number" ]] && ip_number="1"
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
	fi
	# Se $ip for um endereço IP privado, o servidor deve estar atrás de um NAT
	if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo
		echo "Este servidor está rodando atrás de uma NAT. Qual é o endereço IPv4 público ou domínio?"
		# Obter o endereço público e limpar com o grep
		get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
		read -p "Endereço IPv4 Público / domínio [$get_public_ip]: " public_ip
		# Se o serviço checkip não estiver disponível e o usuário não fornecer entrada, pergunte novamente
		until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
			echo "Entrada inválida"
			read -p "Endereço IPv4 Público / domínio: " public_ip
		done
		[[ -z "$public_ip" ]] && public_ip="$get_public_ip"
	fi
	# Se o sistema tiver apenas um único IPv6, ele será usado automaticamente
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
	fi
	# Se o sistema tiver multiplos IPv6, ele irá perguntar qual usar
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
		number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
		echo
		echo "Qual endereço IPv6 deve ser usado?"
		ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
		read -p "Endereço IPv6 [1]: " ip6_number
		until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
			echo "$ip6_number: Entrada Inválida."
			read -p "Endereço IPv6 [1]: " ip6_number
		done
		[[ -z "$ip6_number" ]] && ip6_number="1"
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
	fi
	echo
	echo "Qual protocolo de OpenVPN deve ser usado?"
	echo "   1) UDP (recomendado)"
	echo "   2) TCP"
	read -p "Protocolo [1]: " protocol
	until [[ -z "$protocol" || "$protocol" =~ ^[12]$ ]]; do
		echo "$protocol: Entrada Inválida."
		read -p "Protocolo [1]: " protocol
	done
	case "$protocol" in
		1|"") 
		protocol=udp
		;;
		2) 
		protocol=tcp
		;;
	esac
	echo
	echo "Qual porta o OpenVPN deve ouvir?"
	read -p "Porta (Padrão 1194): " port
	until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
		echo "$port: Porta Inválida."
		read -p "Porta (Padrão 1194): " port
	done
	[[ -z "$port" ]] && port="1194"
	echo
	echo "Selecione o servidor DNS para este cliente:"
	echo "   1) Servidor de Resolução Atual"
	echo "   2) Google"
	echo "   3) 1.1.1.1"
	echo "   4) OpenDNS"
	echo "   5) Quad9"
	echo "   6) AdGuard"
	read -p "Servidor DNS [1]: " dns
	until [[ -z "$dns" || "$dns" =~ ^[1-6]$ ]]; do
		echo "$dns: Entrada Inválida."
		read -p "Servidor DNS [1]: " dns
	done
	echo
	echo "Entre com o nome do primeiro cliente:"
	read -p "Nome [client]: " unsanitized_client
	# Permitir um conjunto limitado de caracteres para evitar conflitos
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	[[ -z "$client" ]] && client="client"
	echo
	echo "Instalação do OpenVPN está pronta para começar."
	# Instale um firewall se firewalld ou iptables ainda não estiverem disponíveis
	if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
		if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			firewall="firewalld"
			# Não queremos habilitar o firewalld silenciosamente, então damos um aviso sutil
			# Se o usuário continuar, o firewalld será instalado e habilitado durante a configuração
			echo "firewalld, é necessário para gerenciar as Routing Tables, também será instalado."
		elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			# iptables é muito menos invasivo que firewalld, então nenhum aviso é dado
			firewall="iptables"
		fi
	fi
	read -n1 -r -p "Aperte qualquer tecla para continuar..."
	# Se estiver executando dentro de um contêiner, desative LimitNPROC para evitar conflitos
	if systemd-detect-virt -cq; then
		mkdir /etc/systemd/system/openvpn-server@server.service.d/ 2>/dev/null
		echo "[Service]
LimitNPROC=infinity" > /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
	fi
	if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
		apt-get update
		apt-get install -y openvpn openssl ca-certificates $firewall
	elif [[ "$os" = "centos" ]]; then
		yum install -y epel-release
		yum install -y openvpn openssl ca-certificates tar $firewall
	else
		# Senão, OS deve ser Fedora
		dnf install -y openvpn openssl ca-certificates tar $firewall
	fi
	# Se o firewalld já estiver sido instalado, ative
	if [[ "$firewall" == "firewalld" ]]; then
		systemctl enable --now firewalld.service
	fi
	# conseguir o easy-rsa
	easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.8/EasyRSA-3.0.8.tgz'
	mkdir -p /etc/openvpn/server/easy-rsa/
	{ wget -qO- "$easy_rsa_url" 2>/dev/null || curl -sL "$easy_rsa_url" ; } | tar xz -C /etc/openvpn/server/easy-rsa/ --strip-components 1
	chown -R root:root /etc/openvpn/server/easy-rsa/
	cd /etc/openvpn/server/easy-rsa/
	# Crie a PKI, configure a CA e os certificados de servidor e cliente
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client" nopass
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	# Mova as coisas se necessárias
	cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server
	# A CRL é lida com cada conexão do cliente, enquanto o OpenVPN é descartado para ninguém
	chown nobody:"$group_name" /etc/openvpn/server/crl.pem
	# Sem +x no diretório, o OpenVPN não pode executar um stat() no arquivo CRL
	chmod o+x /etc/openvpn/server/
	# Gerar chaves para o tls-crypt
	openvpn --genkey --secret /etc/openvpn/server/tc.key
	# Crie o arquivo de parâmetros DH usando o grupo ffdhe2048 predefinido
	echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > /etc/openvpn/server/dh.pem
	# Gera server.conf
	echo "local $ip
port $port
proto $protocol
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-crypt tc.key
topology subnet
server 10.8.0.0 255.255.255.0" > /etc/openvpn/server/server.conf
	# IPv6
	if [[ -z "$ip6" ]]; then
		echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server/server.conf
	else
		echo 'server-ipv6 fddd:1194:1194:1194::/64' >> /etc/openvpn/server/server.conf
		echo 'push "redirect-gateway def1 ipv6 bypass-dhcp"' >> /etc/openvpn/server/server.conf
	fi
	echo 'ifconfig-pool-persist ipp.txt' >> /etc/openvpn/server/server.conf
	# DNS
	case "$dns" in
		1|"")
			# Localiza o resolv.conf
			# Necessário para sistemas que executam systemd-resolved
			if grep -q '^nameserver 127.0.0.53' "/etc/resolv.conf"; then
				resolv_conf="/run/systemd/resolve/resolv.conf"
			else
				resolv_conf="/etc/resolv.conf"
			fi
			# Obtenha os resolvedores de resolv.conf e use-os para o OpenVPN
			grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read line; do
				echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server/server.conf
			done
		;;
		2)
			echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server/server.conf
		;;
		3)
			echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server/server.conf
		;;
		4)
			echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server/server.conf
		;;
		5)
			echo 'push "dhcp-option DNS 9.9.9.9"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 149.112.112.112"' >> /etc/openvpn/server/server.conf
		;;
		6)
			echo 'push "dhcp-option DNS 94.140.14.14"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 94.140.15.15"' >> /etc/openvpn/server/server.conf
		;;
	esac
	echo "keepalive 10 120
cipher AES-256-CBC
user nobody
group $group_name
persist-key
persist-tun
verb 3
crl-verify crl.pem" >> /etc/openvpn/server/server.conf
	if [[ "$protocol" = "udp" ]]; then
		echo "explicit-exit-notify" >> /etc/openvpn/server/server.conf
	fi
	# Habilite net.ipv4.ip_forward para o sistema
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn-forward.conf
	# Ativar sem aguardar por uma reinicialização ou reinicialização do serviço
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if [[ -n "$ip6" ]]; then
		# Habilite net.ipv6.conf.all.forwarding para o sistema
		echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-openvpn-forward.conf
		# Ativar sem aguardar por uma reinicialização ou reinicialização do serviço
		echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
	fi
	if systemctl is-active --quiet firewalld.service; then
		# Usando regras permanentes e não permanentes para evitar recarga do firewalld
		# Não usamos --add-service=openvpn porque isso só funcionaria com
		# a porta e o protocolo padrão.
		firewall-cmd --add-port="$port"/"$protocol"
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --add-port="$port"/"$protocol"
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
		# Define o NAT para a sub-rede VPN
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
		if [[ -n "$ip6" ]]; then
			firewall-cmd --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --permanent --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
			firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
		fi
	else
		# Crie um serviço para configurar regras de iptables persistentes
		iptables_path=$(command -v iptables)
		ip6tables_path=$(command -v ip6tables)
		# nf_tables não está disponível como padrão em kernels OVZ. Então use iptables-legacy
		# se estivermos em OVZ, com um backend nf_tables e iptables-legacy está disponível.
		if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
			iptables_path=$(command -v iptables-legacy)
			ip6tables_path=$(command -v ip6tables-legacy)
		fi
		echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStart=$iptables_path -I INPUT -p $protocol --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStop=$iptables_path -D INPUT -p $protocol --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/openvpn-iptables.service
		if [[ -n "$ip6" ]]; then
			echo "ExecStart=$ip6tables_path -t nat -A POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStart=$ip6tables_path -I FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -t nat -D POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStop=$ip6tables_path -D FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/openvpn-iptables.service
		fi
		echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/openvpn-iptables.service
		systemctl enable --now openvpn-iptables.service
	fi
	# Se o SELinux estiver habilitado e uma porta personalizada foi selecionada, precisamos disso
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
		# Instale semanage se ainda não estiver presente
		if ! hash semanage 2>/dev/null; then
			if [[ "$os_version" -eq 7 ]]; then
				# Centos 7
				yum install -y policycoreutils-python
			else
				# CentOS 8 ou Fedora
				dnf install -y policycoreutils-python-utils
			fi
		fi
		semanage port -a -t openvpn_port_t -p "$protocol" "$port"
	fi
	# Se o servidor estiver atrás de uma NAT, use o Endereço IP correto.
	[[ -n "$public_ip" ]] && ip="$public_ip"
	# client-common.txt é criado para que tenhamos um modelo para adicionar mais usuários posteriormente
	echo "client
dev tun
proto $protocol
remote $ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
ignore-unknown-option block-outside-dns
block-outside-dns
verb 3" > /etc/openvpn/server/client-common.txt
	# Ativa e inicializa os serviços do OpenVPN
	systemctl enable --now openvpn-server@server.service
	# Gera customização do client.ovpn
	new_client
	echo
	echo "Concluido!"
	echo
	echo "A configuração do cliente está disponível em:" ~/"$client.ovpn"
	echo "Novos clientes podem ser adicionados rodando este script novamente."
else
	clear
	echo "OpenVPN já está instalado."
	echo
	echo "Entre com uma opção:"
	echo "   1) Adicionar um novo cliente"
	echo "   2) Revogar um cliente existente"
	echo "   3) Remover OpenVPN"
	echo "   4) Sair"
	read -p "Opção: " option
	until [[ "$option" =~ ^[1-4]$ ]]; do
		echo "$option: Seleção Inválida."
		read -p "Opção: " option
	done
	case "$option" in
		1)
			echo
			echo "Informe um nome para o cliente:"
			read -p "Nome: " unsanitized_client
			client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			while [[ -z "$client" || -e /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt ]]; do
				echo "$client: Entrada Inválida."
				read -p "Nome: " unsanitized_client
				client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			done
			cd /etc/openvpn/server/easy-rsa/
			EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client" nopass
			# Gera a customização do client.ovpn
			new_client
			echo
			echo "$client adicionado com sucesso. Chave de configuração está disponível em:" ~/"$client.ovpn"
			exit
		;;
		2)
			# Esta opção poderia ser documentada um pouco melhor e talvez até simplificada
			number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$number_of_clients" = 0 ]]; then
				echo
				echo "Não há clientes existentes!"
				exit
			fi
			echo
			echo "Selecione um cliente para revogar:"
			tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			read -p "Cliente: " client_number
			until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
				echo "$client_number: Entrada Inválida."
				read -p "Cliente: " client_number
			done
			client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
			echo
			read -p "Deseja realmente revogar o cliente $client ? [s/N]: " revoke
			until [[ "$revoke" =~ ^[sSnN]*$ ]]; do
				echo "$revoke: Entrada Inválida."
				read -p "Deseja realmente revogar o cliente $client ? [s/N]: " revoke
			done
			if [[ "$revoke" =~ ^[sS]$ ]]; then
				cd /etc/openvpn/server/easy-rsa/
				./easyrsa --batch revoke "$client"
				EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
				rm -f /etc/openvpn/server/crl.pem
				cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
				chown nobody:"$group_name" /etc/openvpn/server/crl.pem
				echo
				echo "Cliente $client foi revogado!"
			else
				echo
				echo "Pedido de Revogação de $client Cancelado!"
			fi
			exit
		;;
		3)
			echo
			read -p "Tem certeza que deseja remover OpenVPN? [s/N]: " remove
			until [[ "$remove" =~ ^[sSnN]*$ ]]; do
				echo "$remove: Seleção Inválida."
				read -p "Confirm OpenVPN removal? [s/N]: " remove
			done
			if [[ "$remove" =~ ^[sS]$ ]]; then
				port=$(grep '^port ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				protocol=$(grep '^proto ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				if systemctl is-active --quiet firewalld.service; then
					ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24' | grep -oE '[^ ]+$')
					# Usando regras permanentes e não permanentes para evitar um recarregamento do firewall.
					firewall-cmd --remove-port="$port"/"$protocol"
					firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --permanent --remove-port="$port"/"$protocol"
					firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
					if grep -qs "server-ipv6" /etc/openvpn/server/server.conf; then
						ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s fddd:1194:1194:1194::/64 '"'"'!'"'"' -d fddd:1194:1194:1194::/64' | grep -oE '[^ ]+$')
						firewall-cmd --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --permanent --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
						firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
					fi
				else
					systemctl disable --now openvpn-iptables.service
					rm -f /etc/systemd/system/openvpn-iptables.service
				fi
				if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
					semanage port -d -t openvpn_port_t -p "$protocol" "$port"
				fi
				systemctl disable --now openvpn-server@server.service
				rm -f /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
				rm -f /etc/sysctl.d/99-openvpn-forward.conf
				if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
					rm -rf /etc/openvpn/server
					apt-get remove --purge -y openvpn
				else
					# Senão, Sistema deve ser CentOS ou Fedora
					yum remove -y openvpn
					rm -rf /etc/openvpn/server
				fi
				echo
				echo "OpenVPN removida!"
			else
				echo
				echo "Remoção de OpenVPN abortada!"
			fi
			exit
		;;
		4)
			exit
		;;
	esac
fi
