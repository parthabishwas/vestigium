#!/usr/bin/env bash
# 90-containers.sh - Container and virtualisation runtime state (16_Containers).

dfir_module_containers() {
    local d="${DFIR_DIR[Containers]}"
    local found=0

    # --- Docker ------------------------------------------------------------
    if dfir_have docker; then
        found=1
        dfir_cmd "docker version"    "${d}/docker/version.txt"    docker version
        dfir_cmd "docker info"       "${d}/docker/info.txt"       docker info
        dfir_cmd "docker containers" "${d}/docker/ps_all.txt"     docker ps -a --no-trunc
        dfir_cmd "docker images"     "${d}/docker/images.txt"     docker images -a --digests --no-trunc
        dfir_cmd "docker volumes"    "${d}/docker/volumes.txt"    docker volume ls
        dfir_cmd "docker networks"   "${d}/docker/networks.txt"   docker network ls
        dfir_sh  "docker inspect all" "${d}/docker/inspect.json" \
            "docker ps -aq 2>/dev/null | xargs -r docker inspect 2>/dev/null"
        dfir_sh  "docker container processes" "${d}/docker/container_processes.txt" '
            for c in $(docker ps -q 2>/dev/null); do
                printf "=== %s (%s) ===\n" "$c" "$(docker inspect -f "{{.Name}}" "$c" 2>/dev/null)"
                docker top "$c" 2>/dev/null
                printf "\n"
            done
            exit 0'
        dfir_sh "docker container logs (tail)" "${d}/docker/container_logs.txt" '
            for c in $(docker ps -aq 2>/dev/null); do
                printf "=== %s ===\n" "$c"
                docker logs --tail 500 --timestamps "$c" 2>&1 | tail -n 500
                printf "\n"
            done
            exit 0'
        [[ -f /etc/docker/daemon.json ]] && dfir_copy /etc/docker/daemon.json "${d}/docker/daemon.json"
        # Writable-layer drift: what changed inside each RUNNING container
        # versus its image. Changes under binary/library/config paths of a
        # running container are a strong implant or tampering signal.
        dfir_sh "docker container diffs" "${d}/docker/container_diffs.txt" '
            printf "Writable-layer changes per RUNNING container (docker diff): A=added C=changed D=deleted.\n"
            printf "sensitive= changes under /bin /sbin /usr/bin /usr/sbin /usr/local /lib /lib64 /etc /root.\n\n"
            for c in $(docker ps -q 2>/dev/null); do
                n=$(docker inspect -f "{{.Name}}" "$c" 2>/dev/null); n=${n#/}
                df=$(docker diff "$c" 2>/dev/null)
                a=$(printf "%s\n" "$df" | grep -c "^A "); ch=$(printf "%s\n" "$df" | grep -c "^C "); dl=$(printf "%s\n" "$df" | grep -c "^D ")
                sv=$(printf "%s\n" "$df" | grep -Ec "^[ACD] (/bin|/sbin|/usr/bin|/usr/sbin|/usr/local|/lib|/lib64|/etc|/root)(/|$)")
                printf "CONTAINER-DRIFT %s name=%s A=%s C=%s D=%s sensitive=%s\n" "$c" "$n" "$a" "$ch" "$dl" "$sv"
            done
            printf "\n--- raw diffs ---\n"
            for c in $(docker ps -q 2>/dev/null); do
                printf "=== %s (%s) ===\n" "$c" "$(docker inspect -f "{{.Name}}" "$c" 2>/dev/null)"
                docker diff "$c" 2>/dev/null | head -n 5000
                printf "\n"
            done
            exit 0'
        dfir_sh "docker socket exposure" "${d}/docker/socket_exposure.txt" '
            printf -- "--- docker socket permissions ---\n"
            ls -la /var/run/docker.sock 2>/dev/null
            printf -- "\n--- containers mounting the docker socket (privilege escalation path) ---\n"
            docker ps -aq 2>/dev/null | xargs -r docker inspect \
                -f "{{.Name}} privileged={{.HostConfig.Privileged}} mounts={{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}" 2>/dev/null |
                grep -E "docker.sock|privileged=true" || printf "(none)\n"
            exit 0'
    fi

    # --- Podman ------------------------------------------------------------
    if dfir_have podman; then
        found=1
        dfir_cmd "podman containers" "${d}/podman/ps_all.txt" podman ps -a --no-trunc
        dfir_cmd "podman images"     "${d}/podman/images.txt" podman images -a
        dfir_cmd "podman info"       "${d}/podman/info.txt"   podman info
        # Writable-layer drift: what changed inside each RUNNING container
        # versus its image. Changes under binary/library/config paths of a
        # running container are a strong implant or tampering signal.
        dfir_sh "podman container diffs" "${d}/podman/container_diffs.txt" '
            printf "Writable-layer changes per RUNNING container (podman diff): A=added C=changed D=deleted.\n"
            printf "sensitive= changes under /bin /sbin /usr/bin /usr/sbin /usr/local /lib /lib64 /etc /root.\n\n"
            for c in $(podman ps -q 2>/dev/null); do
                n=$(podman inspect -f "{{.Name}}" "$c" 2>/dev/null); n=${n#/}
                df=$(podman diff "$c" 2>/dev/null)
                a=$(printf "%s\n" "$df" | grep -c "^A "); ch=$(printf "%s\n" "$df" | grep -c "^C "); dl=$(printf "%s\n" "$df" | grep -c "^D ")
                sv=$(printf "%s\n" "$df" | grep -Ec "^[ACD] (/bin|/sbin|/usr/bin|/usr/sbin|/usr/local|/lib|/lib64|/etc|/root)(/|$)")
                printf "CONTAINER-DRIFT %s name=%s A=%s C=%s D=%s sensitive=%s\n" "$c" "$n" "$a" "$ch" "$dl" "$sv"
            done
            printf "\n--- raw diffs ---\n"
            for c in $(podman ps -q 2>/dev/null); do
                printf "=== %s (%s) ===\n" "$c" "$(podman inspect -f "{{.Name}}" "$c" 2>/dev/null)"
                podman diff "$c" 2>/dev/null | head -n 5000
                printf "\n"
            done
            exit 0'
    fi

    # --- LXD / LXC ---------------------------------------------------------
    if dfir_have lxc; then
        found=1
        dfir_cmd "lxc list"     "${d}/lxd/list.txt"     lxc list
        dfir_cmd "lxc images"   "${d}/lxd/images.txt"   lxc image list
        dfir_cmd "lxc profiles" "${d}/lxd/profiles.txt" lxc profile list
    fi

    # --- Kubernetes / systemd-nspawn / VMs ---------------------------------
    dfir_have kubectl && { found=1; dfir_cmd "kubectl contexts" "${d}/k8s/contexts.txt" kubectl config get-contexts; }
    dfir_have machinectl && dfir_cmd "systemd machines" "${d}/machinectl.txt" machinectl list
    dfir_have virsh && { found=1; dfir_cmd "libvirt domains" "${d}/libvirt/domains.txt" virsh list --all; }
    dfir_have vboxmanage && { found=1; dfir_cmd "virtualbox vms" "${d}/virtualbox/vms.txt" vboxmanage list vms; }

    # --- Container-relevant kernel state ----------------------------------
    dfir_cmd "namespaces in use" "${d}/lsns.txt" lsns
    dfir_sh "cgroup membership of running processes" "${d}/cgroups.txt" '
        for p in /proc/[0-9]*; do
            [ -r "$p/cgroup" ] || continue
            c=$(tr "\n" " " < "$p/cgroup" 2>/dev/null)
            case "$c" in
                *docker*|*containerd*|*kubepods*|*machine.slice*|*lxc*|*podman*)
                    printf "PID %-8s %-30s %s\n" "${p#/proc/}" \
                        "$(tr "\0" " " < "$p/cmdline" 2>/dev/null | cut -c1-30)" "$c" ;;
            esac
        done
        exit 0'

    if (( found == 0 )); then
        printf 'No container or virtualisation runtimes were detected on this host.\n' \
            >"${d}/no-runtimes-detected.txt"
        dfir_log INFO "No container runtimes present"
    fi
    return 0
}
