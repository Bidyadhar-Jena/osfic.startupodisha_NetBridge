from network.monitor import get_network_status


if __name__ == "__main__":
    status = get_network_status()

    print("\n===== NETBRIDGE NETWORK MONITOR =====")
    print(f"Platform: {status['platform']}")
    print(f"Internet: {status['internet']['status']}")
    print(f"Communication: {status['communication']['method']}")
    print("Communication readiness:", status["communication_readiness"])
