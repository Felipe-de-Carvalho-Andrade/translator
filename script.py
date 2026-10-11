
import hashlib
import socket
import sys
import time

# Define o endereço e a porta do serviço.
# Permite informar esses valores pela linha de comando.
HOST = sys.argv[1] if len(sys.argv) > 1 else "fireuai.com.br"
PORTS = [int(sys.argv[2])] if len(sys.argv) > 2 else [55003, 55004]

# Armazena a conexão ativa e os dados recebidos que ainda não foram processados.
sock = None
buf = bytearray()


def recv_until(token, timeout=None):
    """
    Recebe dados até encontrar o marcador especificado.
    Se o tempo limite expirar, retorna None.
    """
    global buf

    # Define o prazo máximo de espera, quando houver um limite.
    deadline = None if timeout is None else time.monotonic() + timeout

    while token not in buf:
        old_timeout = sock.gettimeout()

        if deadline is not None:
            remaining = deadline - time.monotonic()

            if remaining <= 0:
                return None

            sock.settimeout(remaining)

        try:
            # Recebe um bloco de dados da conexão.
            chunk = sock.recv(4096)
        except socket.timeout:
            return None
        finally:
            # Restaura o tempo limite anterior da conexão.
            sock.settimeout(old_timeout)

        if not chunk:
            raise EOFError("Conexão encerrada pelo serviço")

        # Guarda os bytes recebidos para procurar o marcador.
        buf.extend(chunk)

    # Separa os dados até o final do marcador encontrado.
    end = buf.index(token) + len(token)
    out = bytes(buf[:end])
    del buf[:end]

    return out


def recv_exact(count):
    """
    Aguarda até receber exatamente a quantidade de bytes solicitada.
    Mantém no buffer os bytes excedentes para leituras posteriores.
    """
    global buf

    while len(buf) < count:
        chunk = sock.recv(4096)

        if not chunk:
            raise EOFError(
                f"Conexão encerrada durante a leitura de {count} bytes"
            )

        buf.extend(chunk)

    # Retira do buffer somente a quantidade solicitada.
    out = bytes(buf[:count])
    del buf[:count]

    return out


# Tenta conectar-se às portas configuradas e reconhecer o serviço.
connected = False

for port in PORTS:
    candidate = None

    try:
        candidate = socket.create_connection(
            (HOST, port), timeout=4
        )
        candidate.settimeout(5)

        # Inicializa a conexão e o buffer de recebimento.
        sock, buf = candidate, bytearray()

        # Confirma a conexão pela mensagem inicial do desafio.
        if recv_until(
            b"You have 10 attempts to translate the secret.",
            timeout=4
        ) is not None:
            print(f"[+] Conexão realizada: {HOST}:{port}")
            connected = True
            break

        candidate.close()

    except (OSError, EOFError):
        # Fecha a conexão que falhou, se ela tiver sido criada.
        if candidate is not None:
            try:
                candidate.close()
            except OSError:
                pass

# Encerra a execução se nenhuma porta apresentar o serviço esperado.
if not connected:
    raise SystemExit(
        "[-] Não foi possível conectar ao serviço Translator"
    )


try:
    rounds = 0

    while True:
        # Aguarda o início de uma nova rodada.
        if recv_until(
            b"Let me choose a language for you..."
        ) is None:
            raise EOFError("Conexão encerrada durante a leitura")

        rounds += 1

        # Aguarda o marcador que antecede a frase codificada.
        # O tempo limite permite detectar a condição usada pelo script
        # para iniciar a etapa de recuperação.
        phrase = recv_until(
            b"Translate this phrase: ",
            timeout=1.0
        )

        if phrase is None:
            # Prepara uma entrada conhecida de 16 bytes.
            # Esse tamanho corresponde à entrada do SHA-512
            # identificada na análise do programa.
            known = b"A" * 16
            sock.sendall(known)

            # Aguarda os marcadores esperados antes de ler os dados.
            if recv_until(
                b"Translate this phrase: ", timeout=5
            ) is None:
                raise TimeoutError("Tempo limite aguardando a frase")

            if recv_until(b"\x1b[0m", timeout=5) is None:
                raise TimeoutError("Tempo limite aguardando o marcador")

            # Recebe os 64 bytes da frase codificada.
            ciphertext = recv_exact(64)

            # Aguarda o campo de resposta do serviço.
            if recv_until(
                b"Your translation: ", timeout=5
            ) is None:
                raise TimeoutError("Tempo limite aguardando a resposta")

            matches = []

            # Testa hipóteses para diferentes quantidades de bytes
            # conhecidos, completando a entrada com bytes nulos.
            for n in range(17):
                phrase_input = (
                    known[:n] + b"\x00" * (16 - n)
                )

                # Calcula o SHA-512 da entrada candidata e aplica XOR
                # aos bytes recebidos para obter um possível segredo.
                secret = bytes(
                    x ^ y
                    for x, y in zip(
                        ciphertext,
                        hashlib.sha512(phrase_input).digest()
                    )
                )

                # Guarda os resultados que começam com o prefixo
                # esperado para a flag do desafio.
                if secret.startswith(b"UAI{"):
                    flag = secret.split(b"\x00", 1)[0]
                    matches.append((n, flag))

            # Interrompe se nenhuma hipótese produzir um candidato.
            if not matches:
                raise ValueError(
                    "Não foi possível recuperar a flag"
                )

            # Seleciona o primeiro candidato encontrado.
            n, flag = matches[0]

            # Exibe somente a flag recuperada, sem imprimir
            # mensagens intermediárias de diagnóstico.
            print(
                "[+] Flag capturada:",
                flag.decode("ascii", "replace")
            )

            # Envia o candidato ao serviço para validação.
            sock.sendall(flag + b"\n")
            break

        # Nas rodadas normais, consome a frase codificada e aguarda
        # o campo de resposta antes de enviar 64 caracteres A.
        recv_exact(64)

        if recv_until(b"Your translation: ") is None:
            raise EOFError("Campo de resposta não encontrado")

        sock.sendall(b"A" * 64)

finally:
    # Garante o fechamento da conexão ao terminar ou ocorrer um erro.
    if sock is not None:
        try:
            sock.close()
        except OSError:
            pass
