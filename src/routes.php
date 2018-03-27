<?php

use Slim\Http\Request;
use Slim\Http\Response;

// Routes

$app->get('/', function (Request $request, Response $response, array $args) {
	$result = $this->db->query("SELECT count(id) as count from attacks");
	$result = $result->fetch();
	$count = $result['count'];

	if(isset($_GET['ip_address']) && !empty($_GET['ip_address'])) {
		$stmt = $this->db->prepare("SELECT *, attacks.id as attackid FROM attacks JOIN ip_addresses ON attacks.ipid = ip_addresses.id WHERE ip_addresses.ip = :ip_address ORDER by attacks.id DESC LIMIT 10000");
		$stmt->bindparam('ip_address', $_GET['ip_address']);
		$stmt->execute();
		$result = $stmt->fetchAll();
	} else {
		$result = $this->db->query("SELECT *, attacks.id as attackid FROM attacks JOIN ip_addresses ON attacks.ipid = ip_addresses.id ORDER by attacks.start DESC LIMIT 10000");
	}
	
	// Render index view
	$this->renderer->render($response, 'header.html', ['path' => $request->getUri()->getBasePath()]);
	$this->renderer->render($response, 'index.phtml', array(
		'result' => $result
	));
	return;
});

$app->get('/ips', function (Request $request, Response $response, array $args) {
	$result = $this->db->query("SELECT ip, last_attack, count(attacks.id) as count FROM ip_addresses JOIN attacks on attacks.ipid = ip_addresses.id GROUP by ip LIMIT 10000");
	$result2='';
	foreach($result as $re) {
		$re['mode'] = 2;
		$re['l7'] = 0;
		$result2[$re['ip']] = $re;
	}
	
	$vox_list_json = $this->voxility->get_list_json();
	foreach($vox_list_json as $i => $re) {
		if($i == 'account' || $i == 'comment') continue;
		list($i, $j) = @explode('/', $i);
		if(!isset($result2[$i])) { // if ip is not present in database
			$result2[$i] = array(
				'ip' => $i,
				'count' => 0,
				'last_attack' => 'never',
				'mode' => $re->mode,
				'l7' => (int) !$re->no_l7,
			);
		} else {
			$result2[$i] = array_merge($result2[$i], array(
				'mode' => $re->mode,
				'l7' => (int) !$re->no_l7,
			));
		}
	}
	
	// Render index view
	$this->renderer->render($response, 'header.html', ['path' => $request->getUri()->getBasePath()]);
	$this->renderer->render($response, 'ips.html', array(
		'result' => $result2,
		'path' => $request->getUri()->getBasePath()
	));
	return;
});

$app->get('/change_mode/{ip}/{mode}/{no_l7}', function (Request $request, Response $response, array $args) {
	if(!is_numeric($args['mode']) || !is_numeric($args['no_l7'])) {
		return $response->withRedirect('/ips?error', 301);
	}
	$result = $this->voxility->change_mode($args['ip'], $args['mode'], $args['no_l7']);
	return $response->withJson(array('result'=>$result));
});

$app->get('/details/{att_id}', function (Request $request, Response $response, array $args) {
	if(!isset($args['att_id']) || !is_numeric($args['att_id'])) {
		return $response->withRedirect('/', 301);
	}
	
	$result = $this->voxility->get_attack_detail($args['att_id'])->samples;
	$result2 = [];
	foreach($result as $s) {
		$result2[] = array(	
			'timestamp' => date("Y-m-d H:i:s", $s->epoch).'.'.$s->microsecond,
			'protocol' => $this->voxility->get_proto_name($s->proto),
			'source' => $s->src_ip.':'.$s->src_port.' ('.$this->whois->get_host($s->src_ip).')',
			'destination' => $s->dst_ip.':'.$s->dst_port,
			'length' => $s->len_ip.'/'.$s->len_payload.' bytes',
		);
	}
	
	// Render index view
	$this->renderer->render($response, 'header.html', ['path' => $request->getUri()->getBasePath()]);
	$this->renderer->render($response, 'details.phtml', array(
		'result' => $result2
	));
	return;
});

$app->get('/cron', function (Request $request, Response $response, array $args) {
	$voxility = $this->voxility;
	$sql = $this->db;
	
	$attacks = $voxility->get_attacks();

	$sth1 = $sql->prepare("SELECT att_id FROM attacks WHERE att_id = :att_id LIMIT 1");
	$sth2 = $sql->prepare("SELECT id FROM ip_addresses WHERE ip = :ip LIMIT 1");
	$sth3 = $sql->prepare("INSERT INTO ip_addresses (ip, last_attack) values (:ip, UNIX_TIMESTAMP())");
	$sth4 = $sql->prepare("INSERT INTO attacks (ipid, start, end, action, type, att_id) values (:ipid, :start, :end, :action, :type, :att_id)");
	$sth5 = $sql->prepare("UPDATE ip_addresses SET last_attack=:last_attack WHERE id=:ipid");

	$log[] = 'fetch get_last_attacks from voxility';
	foreach($attacks as $attack) {
	// 	var_dump($attack);
		$sth1->bindvalue(':att_id', $attack->att_id);
		$sth1->execute();
		$res = $sth1->fetchAll();
		if(!empty($res)) continue;
		
		$log[] = 'processing att_id='.$attack->att_id;
		
		// add attack info in to database
		$sth2->bindvalue('ip', $attack->ip);
		$sth2->execute();
		$res2 = $sth2->fetchAll();
		if(empty($res2)) {
			$sth3->bindvalue('ip', $attack->ip);
			$sth3->execute();
			$ip_id = $sql->lastInsertId();
		} else {
			$ip_id = $res2[0]['id'];
		}
		
		$sth4->bindvalue('ipid', $ip_id);
		$sth4->bindvalue('start', $attack->start);
		
		$array = date_parse($attack->duration);
		$add_time = intval($array['second']+$array['minute']*60+$array['hour']*3600);
		$end = strtotime($attack->start) + $add_time;
		$end = date("c", $end);
		
		$sth4->bindvalue('end', $end);
		$sth4->bindvalue('action', $attack->action);
		$sth4->bindvalue('type', $attack->type);
		$sth4->bindvalue('att_id', $attack->att_id);
		$sth4->execute();
		
		$sth5->bindvalue('ipid', $ip_id);
		$sth5->bindvalue('last_attack', $end);
		$sth5->execute();
		$log[] = 'added new att_id='.$attack->att_id;
	}
	return $response->withJson(array('status'=>'success','log'=>$log));
});