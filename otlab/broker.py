"""Project-local single-node KRaft broker, bound to loopback only."""
import argparse
from pathlib import Path
import os
import socket
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
KAFKA = ROOT / 'runtime/tools/kafka_2.13-4.1.2'


def java_path():
    candidates = []
    if os.environ.get('JAVA_HOME'):
        candidates.append(Path(os.environ['JAVA_HOME']) / 'bin/java.exe')
    candidates.extend(sorted(Path('C:/Program Files/Java').glob('jdk-*/bin/java.exe'), reverse=True))
    for path in candidates:
        if path.is_file():
            return path
    raise RuntimeError('Set JAVA_HOME to an installed Java 17+ JDK')


def available_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class Broker:
    def __init__(self, folder, port=19092, controller_port=19093):
        self.folder = Path(folder).resolve()
        self.folder.mkdir(parents=True, exist_ok=True)
        self.port = port
        self.controller_port = controller_port
        self.process = None
        self.log = None
        if not (KAFKA / 'libs').is_dir():
            raise RuntimeError('Kafka runtime missing; run setup_kafka.py')
        self.java = str(java_path())
        self.base = [self.java, '-Xms256m', '-Xmx512m',
                     '-Dlog4j2.configurationFile=' + str(KAFKA / 'config/tools-log4j2.yaml'),
                     '-cp', str(KAFKA / 'libs/*')]
        self.config = self.folder / 'server.properties'
        self.config.write_text('\n'.join([
            'process.roles=broker,controller', 'node.id=1',
            f'controller.quorum.bootstrap.servers=127.0.0.1:{controller_port}',
            f'listeners=PLAINTEXT://127.0.0.1:{port},CONTROLLER://127.0.0.1:{controller_port}',
            f'advertised.listeners=PLAINTEXT://127.0.0.1:{port}',
            'controller.listener.names=CONTROLLER',
            'listener.security.protocol.map=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT',
            'inter.broker.listener.name=PLAINTEXT',
            'log.dirs=' + (self.folder / 'data').as_posix(),
            'offsets.topic.replication.factor=1', 'transaction.state.log.replication.factor=1',
            'transaction.state.log.min.isr=1', 'group.initial.rebalance.delay.ms=0',
            'num.partitions=1', 'auto.create.topics.enable=false',
            'log.retention.hours=24', 'log.segment.bytes=10485760',
        ]) + '\n', encoding='utf-8')

    def tool(self, *args):
        result = subprocess.run(self.base + ['kafka.tools.StorageTool', *args],
                                capture_output=True, text=True, timeout=40,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        return result.stdout.strip()

    def start(self):
        for port in (self.port, self.controller_port):
            with socket.socket() as check:
                check.bind(('127.0.0.1', port))
        if not (self.folder / 'data/meta.properties').exists():
            cluster = self.tool('random-uuid').splitlines()[-1]
            self.tool('format', '--standalone', '-t', cluster, '-c', str(self.config))
        self.log = (self.folder / 'broker.log').open('a', encoding='utf-8')
        self.process = subprocess.Popen(self.base + ['kafka.Kafka', str(self.config)],
                                        stdout=self.log, stderr=self.log, cwd=ROOT,
                                        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError('Kafka exited; inspect ' + str(self.folder / 'broker.log'))
            try:
                with socket.create_connection(('127.0.0.1', self.port), timeout=.5):
                    return self
            except OSError:
                time.sleep(.2)
        self.stop()
        raise RuntimeError('Kafka startup timed out')

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.log:
            self.log.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=19092)
    args = parser.parse_args()
    broker = Broker(ROOT / 'runtime/kafka-local', args.port, args.port + 1)
    try:
        broker.start()
        print(f'Kafka ready on 127.0.0.1:{args.port}; Ctrl+C stops it.', flush=True)
        broker.process.wait()
    except KeyboardInterrupt:
        pass
    finally:
        broker.stop()
