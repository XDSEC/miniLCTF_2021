<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
</head>
<body>
    <a>访问点东西？</a><br/><br/>
	<div>
	   	<form action="index.php" method="POST" >
			<input type="text" name="url" placeholder="Your url" />
		</form><br/>
	</div>
</body>
</html>

<?php
function curl($url){  
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_HEADER, 0);
    echo curl_exec($ch);
    curl_close($ch);
}

if(isset($_POST['url'])){
	$url = $_POST['url'];
	if(preg_match('/file\:\/\/|dict|\.\.\/|127.0.0.1|localhost/is', $url,$match)) {
		die('这样子可不行哦');
	}
	curl($url);
}

if(isset($_POST['minisecret'])){
	system('ifconfig eth1');
}
?>
