"""Download a pinned Apache Kafka runtime into ignored project storage."""
import hashlib
from pathlib import Path
import tarfile
import urllib.request


def setup():
    root = Path(__file__).resolve().parent / 'runtime/tools'
    root.mkdir(parents=True, exist_ok=True)
    archive = root / 'kafka_2.13-4.1.2.tgz'
    base = 'https://downloads.apache.org/kafka/4.1.2/'
    if not archive.exists():
        print('Downloading Kafka 4.1.2 (approximately 127 MiB)...', flush=True)
        urllib.request.urlretrieve(base + archive.name, archive)
    with urllib.request.urlopen(base + archive.name + '.sha512', timeout=30) as response:
        published = response.read().decode()
    expected = ''.join(published.split(':', 1)[1].split()).lower()
    if hashlib.sha512(archive.read_bytes()).hexdigest() != expected:
        raise RuntimeError('Kafka archive checksum mismatch; archive was not extracted')
    if not (root / 'kafka_2.13-4.1.2/libs').is_dir():
        with tarfile.open(archive) as bundle:
            bundle.extractall(root, filter='data')
    print('Kafka 4.1.2 ready; SHA-512 matches the Apache download checksum.')


if __name__ == '__main__':
    setup()
