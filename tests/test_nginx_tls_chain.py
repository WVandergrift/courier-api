from pathlib import Path


def test_controller_origins_use_esp32_compatible_tls_chain():
    nginx = Path("deploy/nginx.conf").read_text()
    blocks = nginx.split("server {")
    controller_hosts = {
        "firmware.emberhome.lighting": False,
        "emberhome.lighting www.emberhome.lighting": False,
    }

    for block in blocks:
        if "listen 443 ssl" not in block:
            continue
        for hosts in controller_hosts:
            if f"server_name {hosts}" not in block:
                continue
            assert "ssl_certificate /etc/letsencrypt/firmware-fullchain.pem;" in block
            controller_hosts[hosts] = True

    assert all(controller_hosts.values())
