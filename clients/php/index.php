<html>
<body>
<?php

// NO UINT SUPPORT:  only nonces <= 2147483647 ( 0x0FFFFFFF )

// Hard Coded Salt - CHANGE THIS!!!
$salt = "c2c565a8c7dc220ed7d9ff2f34b40dae7864ef0b8189557f0d3b7360ef34e1cd";

$nonce_start;
$nonce_end;
$block_header;

if ((!isset($_GET['nonce_start'])  or $_GET['nonce_start'] == '') or
    (!isset($_GET['nonce_end'])    or $_GET['nonce_end'] == '') or
    (!isset($_GET['block_header']) or $_GET['block_header'] == '') or
    (!isset($_GET['signature'])    or $_GET['signature'] == '')){
    header("HTTP/1.1 500 Internal Server Error");
    echo "Internal Server Error";
    exit;
}

$nonce_start  = (int) $_GET['nonce_start'];
$nonce_end    = (int) $_GET['nonce_end'];
$block_header = $_GET['block_header'];
$signature    = $_GET['signature'];

// Check Signature
if (strcasecmp($signature, hash('sha256', pack('H*', $block_header).pack('H*', $salt))) != 0){
    header("HTTP/1.1 401 Unauthorized");
    echo "Unauthorized";
    exit;
}

$share_cmp    = pack('H*', "00000000");

$pre_hash = hash_init('sha256');
hash_update($pre_hash, pack('H*', $block_header));

for ($nonce = $nonce_start; $nonce <= $nonce_end; $nonce++) {
    $hash = hash_copy($pre_hash);
    hash_update($hash, pack('V', $nonce));
    $mid_binary_string = hash_final($hash, True);
    $final_binary_string = hash('sha256', $mid_binary_string, True);
    // Check last 4 bytes for share
    if (substr_compare($final_binary_string, $share_cmp, 28, 32) == 0){
        $resp = array('share_found' => True, 'nonce' => $nonce, 'nonce_start' => $nonce_start, 'nonce_end' => $nonce);
		echo json_encode($resp);
		exit;
    }
}

$resp = array('share_found' => False, 'nonce' => -1, 'nonce_start' => $nonce_start, 'nonce_end' => $nonce_end);
echo json_encode($resp);

?>
</body>
</html>