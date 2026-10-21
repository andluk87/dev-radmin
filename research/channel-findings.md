# Канал CChannel и отдельный RSA-обмен RSession

Добавлен `internal/channel`: независимая Go-реализация экспортируемого CChannel
из исходной `shelper.dll`. В лабораторном `srp-lab` она включается параметром
`-channel-record`. Начальная последовательность сопоставлена с захватом в
[дополнительном исследовании](bootstrap-findings.md); Windows-клиент на этот
стенд ещё не перенаправляется.

## Подтверждённый CChannel

Проверено исполнением неизменённой DLL в ограниченном x86-эмуляторе с тем же
SHA-256, что в [SRP-исследовании](srp-findings.md). Проверки не отключались.

* `CreateClient` и `CreateServer` экспортируют один адрес `0x1006a8b0`.
  Аргументы: указатель ключа шифрования, длина 32, указатель ключа расшифрования,
  длина 32. Направления ключей задаёт вызывающая сторона.
* AES-256-CBC. Два независимых начальных IV равны нулю; последующие сообщения
  продолжают CBC-цепочку своего направления. IV не передаётся в каждом сообщении.
* Для непустого payload длины L полный размер T = `(floor((L+8)/16)+1)*16`.
  Перед шифрованием: payload, заполнение `0xcc`, 8 байт контрольной суммы,
  один байт `T-L` (9..24).
* Контрольная сумма вычисляется по первым `T-9` байтам: сложение little-endian
  64-битных слов по модулю 2^64, остаток как дополненное нулями LE-слово;
  затем MD4 от восьми LE-байтов суммы. В результате digest[i] + digest[i+8]
  по модулю 256 даёт каждый из восьми выходных байтов.
* Декодер проверяет длину, завершающий байт и checksum. Само заполнение не обязано
  равняться `0xcc`, если checksum верен. Go сохраняет это наблюдаемое поведение.

Независимое определение AES проверено Python cryptography, MD4 — OpenSSL legacy
provider. Go не использует внешних криптографических зависимостей; MD4 реализован
только для фиксированного восьмибайтового входа этой суммы.

Проверены 26 последовательных DLL → DLL сообщений (13 размеров в каждом
направлении), от 1 до 1024 байт, включая границы заполнения и размеры SRP.
В Go проверяется побайтовое совпадение шифротекста и расшифрование всех исходных
векторов, а также отказ на повреждённых/неполных записях и нарушении порядка.
Три отклоняемых примера дополнительно проверены DLL.
`testdata/native-channel.json` содержит только публичные синтетические ключи.

Через Docker проверена цепочка DLL SRP-клиент → DLL CChannel → TCP → Go CChannel →
Go SRP-сервер. Успешный пароль завершает взаимную аутентификацию; неверный пароль и
повреждённый M1 дают `reason=authentication`; повреждение зашифрованной записи даёт
`reason=channel`. Ключи и пароли не выводятся в журнал. После ошибки записи
Go-контекст канала окончательно отклоняет дальнейшую обработку.

Это устаревшая совместимость: checksum не является ключевым MAC, а CBC с таким
форматом не заменяет современный AEAD. Лабораторный сервис публикуется только на
localhost и не предназначен для промышленного VPN.

## Повторить тест шифрованного SRP в Docker

Сначала выполнить подготовку из [srp-findings.md](srp-findings.md): получить
собственную DLL, проверенную таблицу CP1252, Python-окружение и синтетический
`lab-record.json`. Здесь нет дополнительных Python-зависимостей.

```bash
.venv/bin/python research/channel_interop.py \
  --dll /path/to/shelper.dll --mapping /tmp/radmin-bestfit1252.txt \
  --write-channel-record ./channel-record.json --output /tmp/radmin-channel.json
sha256sum -c bin/srp-lab.sha256
# Только публичные синтетические данные; контейнер работает с UID 65532.
chmod 0444 lab-record.json channel-record.json
docker compose --profile srp-lab build srp-lab
SRP_LAB_RECORD="$PWD/lab-record.json" \
  docker compose -p dev-radmin-research --profile srp-lab run \
  --name dev-radmin-channel-lab -d --no-deps \
  -p 127.0.0.1:17303:17303 \
  -v "$PWD/channel-record.json:/run/channel-record.json:ro" \
  srp-lab -listen :17303 -record /run/srp-record.json \
  -channel-record /run/channel-record.json
.venv/bin/python research/channel_interop.py \
  --dll /path/to/shelper.dll --mapping /tmp/radmin-bestfit1252.txt \
  --server-address 127.0.0.1:17303 --output /tmp/radmin-encrypted-srp.json
docker logs dev-radmin-channel-lab
# После проверки:
docker rm -f dev-radmin-channel-lab
```

Выходные файлы должны ещё не существовать. Уникальное имя контейнера в команде
также должно быть свободно. Генерация новых векторов: добавить
`--write-vectors /tmp/native-channel.json`; файл фикстур в Git уже существует.
Публичные фиксированные ключи нужны только для проверки CChannel; согласования
ключей реальным управляющим протоколом эта команда не выполняет.

## RSession: что установлено отдельно

С собственным случайным RSA-ключом 1536 бит выполнены оригинальные
`SHelper_RSession_CreateClient`, `CreateServer`, `GetNextBuffer`, `GetKey`.
Стороны завершили обмен и получили одинаковые 64 байта ключевого материала.
Независимое RSA-расшифрование Python cryptography подтвердило PKCS#1 v1.5 и
структуру открытого текста: три uint32 LE, затем 64 случайных байта, всего 76 байт.
Весь ключевой материал остаётся в памяти и не попадает в отчёт.

Последовательность тел: клиент 192 байта, сервер 4 байта, завершение клиента без
выходного тела. Сервер возвращает свой uint32 LE. Это наблюдение API и передачи
ключевого материала; оно не является доказательством взаимной аутентификации.

```bash
.venv/bin/pip install -r research/rsession-requirements.txt
.venv/bin/python research/rsession_interop.py \
  --dll /path/to/shelper.dll --mapping /tmp/radmin-bestfit1252.txt \
  --output /tmp/radmin-rsession.json
```

Хронология захвата позднее уточнена: первый ответ сервера имеет 4 байта и идёт
после клиентских 4 и 192 байт; 256 байт — уже следующий ответ. Добавлена
[полная начальная цепочка RSA → CChannel → SRP на Go](bootstrap-findings.md),
проверенная через Docker на собственном RSA-ключе.

## Дополнение: смена ключа

Добавлены шесть нативных векторов после смены ключа с сохранением IV и метод
Go `Rekey`. Связь перехода с завершением SRP описана в
[client-key-findings.md](client-key-findings.md). Для первого запуска на настоящей
Windows подготовлен [отдельный native-check](windows-native-check.md).
