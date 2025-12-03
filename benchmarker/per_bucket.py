import sys

from benchmarker.models.secretbench import TestingScope


def run():

    dataset_location = sys.argv[1]
    target_dir = sys.argv[2]
    bucket_dir = sys.argv[3]
    verification_dir = sys.argv[4]

    scope = TestingScope()
    scope.init(
        bucket_dir=bucket_dir,
        target_dir=target_dir,
        dataset_location=dataset_location,
        verification_dir=verification_dir,
    )
    scope.start_per_bucket()

    print()


if __name__ == '__main__':
    run()
