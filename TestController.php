<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;

class TestController extends Controller
{

    public function home(Request $request)
    {
        echo 2;die;
    }

    public function encryptData(Request $request)
    {
        $str = $request->getContent();
        dd($str);
    }

    public function decryptData(Request $request)
    {

        $str = $request->getContent();
//        $str = "eyJpdiI6IlpKS1c5amFtRktSelhjWWF3T1dEMEE9PSIsInZhbHVlIjoiSFZGdGdoWEJjaWpyNURnYnlhZWl0THYxeU1obzNBZkpcL2cwaFJuYWRYTmZ4bjJOQVIzcU5Rd25HMFBZaVNTcUh4cXdCT1g1QlFZUzlRaWt2ZEs2M0dRPT0iLCJtYWMiOiI4NDc1NDVmYmFlZWRkODdkN2ZmOTRlZDY2ODg0MzE1OTMyMTAxYjY2OTE2NTY4NWIxMDNiN2E5MWM1MTc2ZWMxIn0=";
        $deStr = aesDecrypt($str, config('app.encrypt_key'));
        dd($deStr);
    }

    public static function detectNumberFormat(string $value): ?string {
        if (preg_match('/^0x[0-9a-f]+$/i', $value)) {
            return 'hex'; // 十六进制（如 "0x2A"）
        } elseif (preg_match('/^0b[01]+$/i', $value)) {
            return 'binary'; // 二进制（如 "0b101010"）
        } elseif (is_numeric($value)) {
            return 'decimal'; // 十进制（如 "42"）
        }
        return null; // 无法确定或非数字
    }

    public function encryptDataHmac(Request $request)
    {
        $str = $request->getContent();// 必须是json字符串
        $ivLength = openssl_cipher_iv_length(config('app.cipher'));// 根据模式获取iv字节数
        $iv = openssl_random_pseudo_bytes($ivLength);// 'aes-256-cbc'模式 16字节
        $enStr = aesEncryptHmac($str, $iv, config('app.encrypt_key'), $method = 'aes-256-cbc');// 二进制
        $hmac = makeHashHmac($enStr, $iv, config('app.hmac_key'), $mod = "sha256", $binary = 'true');
        $error = openssl_error_string();
        $enData = base64_encode($iv.$enStr.$hmac);
//        dd(strlen($hmac),strlen(bin2hex($hmac)));
        dd('收到的正文:'.$str, 'iv十六进制:'.bin2hex($iv), '生成Hmac十六进制:'.bin2hex($hmac), '密文正文:'.$enStr, '提交正文:'.$enData, '加密错误信息:'.$error);
    }

    public function decryptDataHmac(Request $request)
    {
        $reData = trim($request->getContent());
        $data = base64_decode($reData);
        $iv = substr($data, 0, 16); //前 16 字节是iv
        $enStr = substr($data, 16, -32); //中间是数据密文
        $reHmac = substr($data, -32); // 最后 32 字节是HMAC-SHA256签名
        if(!is_string($reHmac)) { echo 'hmac_sign is not string';exit();}
        // 验签
        $hmac = makeHashHmac($enStr, $iv, config('app.hmac_key'));
//        dd($reHmac, $hmac, hashEquals($reHmac, $hmac));
        $result = hashEquals($reHmac, $hmac);
        if(!$result) {echo ('hmac_sign error');}
        // 解密
        $deStr = aesDecryptHmac($enStr, $iv, config('app.encrypt_key'));
        dd('收到的正文:'.$reData, "iv:".bin2hex($iv), '密文正文:'.bin2hex($enStr), '收到的Hmac:'.bin2hex($reHmac), '生成的Hmac：'.bin2hex($hmac), 'Hmac验签结果:'.$result, '解密正文:'.$deStr);
    }



}
