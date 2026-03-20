import json
import logging
import os
import shlex
import shutil
import subprocess
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class _VertexRsBridgeClient:
    def __init__(self, bridge_cmd: str, node_id: str, timeout_seconds: float = 3.0):
        self.bridge_cmd = bridge_cmd
        self.node_id = node_id
        self.timeout_seconds = timeout_seconds
        self._subscriptions: Dict[str, List[Callable[[Dict[str, Any]], None]]] = {}
        self._pending: Dict[str, Dict[str, Any]] = {}
        self._pending_condition = threading.Condition()
        self._request_counter = 0
        args = shlex.split(bridge_cmd, posix=False)
        if not args:
            raise RuntimeError("VERTEX_RS_BRIDGE_CMD is empty")
        executable = args[0]
        resolved_executable = shutil.which(executable) if not os.path.isabs(executable) else executable
        if resolved_executable is None:
            raise RuntimeError(
                f"vertex-rs bridge executable not found: {executable}; "
                "set VERTEX_RS_BRIDGE_CMD to an absolute executable path, "
                "for example: E:\\tools\\vertex\\vertex-rs-bridge.exe --host 127.0.0.1 --port 1883 --stdio"
            )
        try:
            self._process = subprocess.Popen(
                args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                bufsize=1,
            )
        except FileNotFoundError as exc:
            raise RuntimeError(
                f"failed to start vertex-rs bridge command: {bridge_cmd}; "
                "verify executable path and arguments in VERTEX_RS_BRIDGE_CMD"
            ) from exc
        self._stdout_thread = threading.Thread(target=self._read_stdout_loop, daemon=True)
        self._stderr_thread = threading.Thread(target=self._read_stderr_loop, daemon=True)
        self._stdout_thread.start()
        self._stderr_thread.start()
        self._request("init", {"node_id": node_id})

    def _next_request_id(self) -> str:
        self._request_counter += 1
        return f"req-{self._request_counter}"

    def _read_stdout_loop(self) -> None:
        stdout = self._process.stdout
        if stdout is None:
            return
        for line in stdout:
            payload = line.strip()
            if not payload:
                continue
            try:
                message = json.loads(payload)
            except Exception:
                logger.warning(f"vertex-rs bridge emitted non-json line: {payload}")
                continue
            message_type = str(message.get("type", ""))
            if message_type == "event":
                topic = str(message.get("topic", ""))
                envelope = dict(message.get("message", {}))
                for callback in self._subscriptions.get(topic, []):
                    try:
                        callback(envelope)
                    except Exception as exc:
                        logger.error(f"vertex-rs bridge callback failed on {topic}: {exc}")
                continue
            request_id = str(message.get("id", ""))
            if request_id:
                with self._pending_condition:
                    self._pending[request_id] = message
                    self._pending_condition.notify_all()

    def _read_stderr_loop(self) -> None:
        stderr = self._process.stderr
        if stderr is None:
            return
        for line in stderr:
            text = line.strip()
            if text:
                logger.warning(f"vertex-rs bridge stderr: {text}")

    def _request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if self._process.poll() is not None:
            raise RuntimeError("vertex-rs bridge process has exited")
        request_id = self._next_request_id()
        wire_message = {
            "id": request_id,
            "method": method,
            "params": params or {},
        }
        stdin = self._process.stdin
        if stdin is None:
            raise RuntimeError("vertex-rs bridge stdin not available")
        stdin.write(json.dumps(wire_message, ensure_ascii=False) + "\n")
        stdin.flush()
        deadline = time.time() + self.timeout_seconds
        with self._pending_condition:
            while request_id not in self._pending:
                remaining = deadline - time.time()
                if remaining <= 0:
                    raise RuntimeError(f"vertex-rs bridge timeout on method {method}")
                self._pending_condition.wait(timeout=remaining)
            response = self._pending.pop(request_id)
        if "error" in response and response["error"]:
            raise RuntimeError(f"vertex-rs bridge error on {method}: {response['error']}")
        return response

    def join_network(self, topic: str) -> None:
        self._request("join_network", {"topic": topic})

    def leave_network(self) -> None:
        try:
            self._request("leave_network", {})
        finally:
            self._process.terminate()

    def subscribe(self, topic: str, callback: Callable[[Dict[str, Any]], None]) -> None:
        self._subscriptions.setdefault(topic, []).append(callback)
        self._request("subscribe", {"topic": topic})

    def publish(self, topic: str, message: Dict[str, Any]) -> None:
        self._request("publish", {"topic": topic, "message": message})

    def get_active_peers(self) -> List[str]:
        response = self._request("get_active_peers", {})
        peers = response.get("result", [])
        if isinstance(peers, list):
            return [str(peer) for peer in peers]
        return []


class _FoxMqttClient:
    def __init__(self, mqtt_addr: str, node_id: str, timeout_seconds: float = 3.0):
        self.node_id = node_id
        self._subscriptions: Dict[str, List[Callable[[Dict[str, Any]], None]]] = {}
        self._known_peers: Dict[str, float] = {}
        self._timeout_seconds = timeout_seconds
        self._connected = threading.Event()
        self._connect_error: Optional[str] = None
        self._mqtt_addr = mqtt_addr
        host, port = self._parse_mqtt_addr(mqtt_addr)
        try:
            import paho.mqtt.client as mqtt
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "mqtt FoxMQ backend requested but paho-mqtt is not installed; "
                "run `python -m pip install paho-mqtt`"
            ) from exc
        callback_api_version = getattr(getattr(mqtt, "CallbackAPIVersion", None), "VERSION2", None)
        if callback_api_version is None:
            self._client = mqtt.Client(client_id=f"foxmq-{node_id}", protocol=mqtt.MQTTv5)
        else:
            self._client = mqtt.Client(
                callback_api_version=callback_api_version,
                client_id=f"foxmq-{node_id}",
                protocol=mqtt.MQTTv5,
            )
        self._client.on_connect = self._on_connect
        self._client.on_message = self._on_message
        try:
            self._client.connect(host, port, keepalive=30)
        except Exception as exc:
            raise RuntimeError(
                f"failed to connect to FoxMQ broker at {mqtt_addr}; "
                "ensure broker is running and mqtt address is reachable"
            ) from exc
        self._client.loop_start()
        if not self._connected.wait(timeout=self._timeout_seconds):
            self._client.loop_stop()
            self._client.disconnect()
            raise RuntimeError(f"timeout waiting for mqtt connection to {mqtt_addr}")
        if self._connect_error:
            self._client.loop_stop()
            self._client.disconnect()
            raise RuntimeError(self._connect_error)

    @staticmethod
    def _parse_mqtt_addr(mqtt_addr: str) -> Tuple[str, int]:
        value = mqtt_addr.strip()
        if not value:
            raise RuntimeError("FOXMQ_MQTT_ADDR is empty")
        if ":" not in value:
            raise RuntimeError(
                f"invalid FOXMQ_MQTT_ADDR value: {mqtt_addr}; expected host:port, for example 127.0.0.1:1883"
            )
        host, port_str = value.rsplit(":", 1)
        host = host.strip()
        if not host:
            raise RuntimeError(f"invalid FOXMQ_MQTT_ADDR value: {mqtt_addr}; host is empty")
        try:
            port = int(port_str)
        except ValueError as exc:
            raise RuntimeError(f"invalid FOXMQ_MQTT_ADDR value: {mqtt_addr}; port must be integer") from exc
        if port <= 0 or port > 65535:
            raise RuntimeError(f"invalid FOXMQ_MQTT_ADDR value: {mqtt_addr}; port must be in 1..65535")
        return host, port

    @staticmethod
    def _reason_code_to_int(reason_code: Any) -> int:
        if isinstance(reason_code, int):
            return reason_code
        value = getattr(reason_code, "value", None)
        if isinstance(value, int):
            return value
        try:
            return int(reason_code)
        except Exception:
            return -1

    def _on_connect(self, client: Any, userdata: Any, flags: Any, reason_code: Any, properties: Any = None) -> None:
        code = self._reason_code_to_int(reason_code)
        if code == 0:
            self._connected.set()
            return
        self._connect_error = f"mqtt connection rejected by broker {self._mqtt_addr} with reason code {code}"
        self._connected.set()

    def _on_message(self, client: Any, userdata: Any, message: Any) -> None:
        try:
            payload = json.loads(message.payload.decode("utf-8"))
        except Exception:
            logger.warning(f"mqtt backend received non-json payload on {message.topic}")
            return
        if not isinstance(payload, dict):
            return
        sender = str(payload.get("_sender", ""))
        if sender and sender != self.node_id:
            self._known_peers[sender] = time.time()
        callbacks = list(self._subscriptions.get(str(message.topic), []))
        for callback in callbacks:
            try:
                callback(dict(payload))
            except Exception as exc:
                logger.error(f"mqtt callback failed on {message.topic}: {exc}")

    def join_network(self, topic: str) -> None:
        _ = topic

    def leave_network(self) -> None:
        self._client.loop_stop()
        self._client.disconnect()

    def subscribe(self, topic: str, callback: Callable[[Dict[str, Any]], None]) -> None:
        self._subscriptions.setdefault(topic, []).append(callback)
        result = self._client.subscribe(topic, qos=1)
        if isinstance(result, tuple) and result:
            code = int(result[0])
            if code != 0:
                raise RuntimeError(f"mqtt subscribe failed on topic {topic}, code={code}")

    def publish(self, topic: str, message: Dict[str, Any]) -> None:
        payload = json.dumps(message, ensure_ascii=False)
        info = self._client.publish(topic, payload, qos=1)
        code = getattr(info, "rc", 0)
        if isinstance(code, int) and code != 0:
            raise RuntimeError(f"mqtt publish failed on topic {topic}, code={code}")

    def get_active_peers(self) -> List[str]:
        return sorted(self._known_peers.keys())


class FoxMQAdapter:
    def __init__(
        self,
        node_id: Optional[str] = None,
        backend: Optional[str] = None,
        bridge_cmd: Optional[str] = None,
        mqtt_addr: Optional[str] = None,
    ):
        self.node_id = node_id or f"node-{uuid.uuid4().hex[:8]}"
        self.peers: List[str] = []
        self._subscriptions: Dict[str, List[Callable[[Dict[str, Any]], None]]] = {}
        self._bridge_cmd = (bridge_cmd or "").strip()
        self._mqtt_addr = (mqtt_addr or "").strip()
        self.backend = (backend or os.getenv("FOXMQ_BACKEND", "mqtt")).strip().lower()
        if self.backend not in {"simulated", "official", "mqtt"}:
            raise ValueError(f"unsupported FoxMQ backend: {self.backend}")
        self._official_client: Optional[Any] = None
        self._official_module_name: Optional[str] = None
        if self.backend == "official":
            self._official_client, self._official_module_name = self._create_official_client()
        if self.backend == "mqtt":
            self._official_client, self._official_module_name = self._create_mqtt_client()

    _shared_bus: Dict[str, List[Callable[[Dict[str, Any]], None]]] = {}
    _shared_peers: List[str] = []

    def _create_official_client(self) -> Tuple[Any, str]:
        bridge_cmd = self._bridge_cmd or os.getenv("VERTEX_RS_BRIDGE_CMD", "").strip()
        if bridge_cmd:
            return _VertexRsBridgeClient(bridge_cmd=bridge_cmd, node_id=self.node_id), f"vertex-rs:{bridge_cmd}"
        raise RuntimeError(
            "official FoxMQ backend requested but Rust bridge command is missing; "
            "set FOXMQ_BACKEND=simulated or set VERTEX_RS_BRIDGE_CMD to a Rust bridge executable"
        )

    def _create_mqtt_client(self) -> Tuple[Any, str]:
        mqtt_addr = self._mqtt_addr or os.getenv("FOXMQ_MQTT_ADDR", "127.0.0.1:1883").strip()
        return _FoxMqttClient(mqtt_addr=mqtt_addr, node_id=self.node_id), f"mqtt:{mqtt_addr}"

    @staticmethod
    def _call_first(target: Any, method_names: Tuple[str, ...], *args: Any, **kwargs: Any) -> bool:
        for method_name in method_names:
            method = getattr(target, method_name, None)
            if callable(method):
                method(*args, **kwargs)
                return True
        return False

    def join_network(self, topic: str = "default") -> None:
        if self.backend in {"official", "mqtt"}:
            if self._official_client is None:
                raise RuntimeError(f"{self.backend} FoxMQ client not initialized")
            joined = self._call_first(self._official_client, ("join_network", "join", "connect"), topic)
            if not joined:
                raise RuntimeError(f"{self.backend} FoxMQ client does not expose join/connect method")
            logger.info(f"Node {self.node_id} joined {self.backend} FoxMQ topic '{topic}'")
            return
        if self.node_id not in FoxMQAdapter._shared_peers:
            FoxMQAdapter._shared_peers.append(self.node_id)
        logger.info(f"Node {self.node_id} joined network topic '{topic}'")

    def leave_network(self) -> None:
        if self.backend in {"official", "mqtt"}:
            if self._official_client is None:
                return
            self._call_first(self._official_client, ("leave_network", "leave", "disconnect"))
            logger.info(f"Node {self.node_id} left {self.backend} FoxMQ network")
            return
        if self.node_id in FoxMQAdapter._shared_peers:
            FoxMQAdapter._shared_peers.remove(self.node_id)
        logger.info(f"Node {self.node_id} left network")

    def subscribe(self, topic: str, callback: Callable[[Dict[str, Any]], None]) -> None:
        if self.backend in {"official", "mqtt"}:
            if self._official_client is None:
                raise RuntimeError(f"{self.backend} FoxMQ client not initialized")
            subscribed = self._call_first(self._official_client, ("subscribe",), topic, callback)
            if not subscribed:
                raise RuntimeError(f"{self.backend} FoxMQ client does not expose subscribe(topic, callback)")
            logger.debug(f"Node {self.node_id} subscribed to {self.backend} topic {topic}")
            return
        if topic not in FoxMQAdapter._shared_bus:
            FoxMQAdapter._shared_bus[topic] = []
        FoxMQAdapter._shared_bus[topic].append(callback)
        logger.debug(f"Node {self.node_id} subscribed to {topic}")

    def publish(self, topic: str, message: Dict[str, Any]) -> None:
        msg_with_meta = message.copy()
        msg_with_meta["_sender"] = self.node_id
        msg_with_meta["_timestamp"] = time.time()

        if self.backend in {"official", "mqtt"}:
            if self._official_client is None:
                raise RuntimeError(f"{self.backend} FoxMQ client not initialized")
            published = self._call_first(self._official_client, ("publish", "send", "broadcast"), topic, msg_with_meta)
            if not published:
                raise RuntimeError(f"{self.backend} FoxMQ client does not expose publish/send/broadcast")
            return

        if topic in FoxMQAdapter._shared_bus:
            for callback in FoxMQAdapter._shared_bus[topic]:
                try:
                    callback(msg_with_meta)
                except Exception as e:
                    logger.error(f"Error processing message on topic {topic}: {e}")

    def broadcast(self, message: Dict[str, Any]) -> None:
        self.publish("global", message)

    def get_active_peers(self) -> List[str]:
        if self.backend in {"official", "mqtt"}:
            if self._official_client is None:
                return []
            getter = getattr(self._official_client, "get_active_peers", None)
            if callable(getter):
                return list(getter())
            peers = getattr(self._official_client, "peers", None)
            if isinstance(peers, list):
                return [str(peer) for peer in peers if str(peer) != self.node_id]
            return []
        return [p for p in FoxMQAdapter._shared_peers if p != self.node_id]

    def backend_info(self) -> Dict[str, str]:
        return {
            "backend": self.backend,
            "module": self._official_module_name or "simulated",
            "node_id": self.node_id,
        }

    @classmethod
    def reset_simulation(cls) -> None:
        cls._shared_bus = {}
        cls._shared_peers = []
