<?php
// DIC configuration

$container = $app->getContainer();

// view renderer
$container['renderer'] = function ($c) {
    $settings = $c->get('settings')['renderer'];
    return new Slim\Views\PhpRenderer($settings['template_path']);
};

// monolog
$container['logger'] = function ($c) {
    $settings = $c->get('settings')['logger'];
    $logger = new Monolog\Logger($settings['name']);
    $logger->pushProcessor(new Monolog\Processor\UidProcessor());
    $logger->pushHandler(new Monolog\Handler\StreamHandler($settings['path'], $settings['level']));
    return $logger;
};

$container['db'] = function ($c) {
	$db = $c->get('settings')['mysql'];
	$sql = new PDO("mysql:host=".$db['host'].";port=3306;dbname=".$db['name'].";charset=UTF8;", $db['user'], $db['pass'], array(
		PDO::ATTR_PERSISTENT=>false,
		PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
		PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
	));
	$sql->query("SET NAMES utf8;");
	return $sql;
};

$container['voxility'] = function ($c) {
	class Voxility {
		private $none;
		private $url = 'http://ips.voxility.com';
		public function __construct() {
			
		}
		private function call_api($url, $params) {
			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url.'?'.http_build_query($params));
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
			$response = curl_exec($ch);
			$response = json_decode($response);
			curl_close($ch);
			return $response;
		}
		public function get_attack_detail($att_id) {
			return $this->call_api($this->url.'/get_packet_samples.php', array('att_id' => $att_id));
		}
		public function get_attacks() {
			return $this->call_api($this->url.'/get_attacks.php', array())->attacks;
		}
		public function get_proto_name($i) {
			switch($i) {
				case 17: return 'udp';
				case 6: return 'tcp';
				case 1: return 'icmp';
				case 47: return 'gre';
				default: return 'unknown, id='.$i;
			}
		}
	}
	return new Voxility();
};

$container['whois'] = function ($c) {
	class Whois {
		private $cached=[];
		public function get_host($addr) {
			if(!isset($this->cached[$addr])) {
				$this->cached[$addr] = gethostbyaddr($addr);
			}
			return $this->cached[$addr];
		}
	}
	return new Whois();
};