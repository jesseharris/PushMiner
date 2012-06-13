<?php

// NO UINT SUPPORT:  only nonces <= 2147483647 ( 0x0FFFFFFF )

$nonce_start;
$nonce_end;
$block_header;

if ((!isset($_GET['nonce_start'])  or $_GET['nonce_start'] == '') or
    (!isset($_GET['nonce_end'])    or $_GET['nonce_end'] == '') or
    (!isset($_GET['block_header']) or $_GET['block_header'] == '')){
    header("HTTP/1.1 500 Internal Server Error");
    echo "Internal Server Error";
    exit;
}

$nonce_start  = (int) $_GET['nonce_start'];
$nonce_end    = (int) $_GET['nonce_end'];
$block_header = $_GET['block_header'];

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