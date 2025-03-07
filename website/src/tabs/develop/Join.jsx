import { useState, useEffect } from "react";
import {Button, Card, Col, Form, Input, Row, Result, Spin, Switch} from "antd";
import axios from "axios";

export const Join = () => {
    const [joinFeeRecord, setJoinFeeRecord] = useState(null);
    const [recordOne, setRecordOne] = useState(null);
    const [recordTwo, setRecordTwo] = useState(null);
    const [joinUrl, setJoinUrl] = useState("https://api.explorer.aleo.org/v1");
    const [joinFee, setJoinFee] = useState("1.0");
    const [privateFee, setPrivateFee] = useState(true);
    const [loading, setLoading] = useState(false);
    const [privateKey, setPrivateKey] = useState(null);
    const [joinError, setJoinError] = useState(null);
    const [status, setStatus] = useState("");
    const [transactionID, setTransactionID] = useState(null);
    const [worker, setWorker] = useState(null);

    function spawnWorker() {
        let worker = new Worker(
            new URL("../../workers/worker.js", import.meta.url),
            { type: "module" },
        );
        worker.addEventListener("message", (ev) => {
            if (ev.data.type == "JOIN_TRANSACTION_COMPLETED") {
                const transactionId = ev.data.joinTransaction;
                setLoading(false);
                setJoinError(null);
                setTransactionID(transactionId);
            } else if (ev.data.type == "ERROR") {
                setJoinError(ev.data.errorMessage);
                setLoading(false);
                setTransactionID(null);
            }
        });
        return worker;
    }

    useEffect(() => {
        if (worker === null) {
            const spawnedWorker = spawnWorker();
            setWorker(spawnedWorker);
            return () => {
                spawnedWorker.terminate();
            };
        }
    }, []);

    const join = async () => {
        setLoading(true);
        setTransactionID(null);
        setJoinError(null);

        const feeAmount = parseFloat(feeString());
        if (isNaN(feeAmount)) {
            setJoinError("Fee is not a valid number");
            setLoading(false);
            return;
        } else if (feeAmount <= 0) {
            setJoinError("Fee must be greater than 0");
            setLoading(false);
            return;
        }

        await postMessagePromise(worker, {
            type: "ALEO_JOIN",
            recordOne: recordOneString(),
            recordTwo: recordTwoString(),
            fee: feeAmount,
            privateFee: privateFee,
            feeRecord: feeRecordString(),
            privateKey: privateKeyString(),
            url: peerUrl(),
        });
    };

    function postMessagePromise(worker, message) {
        return new Promise((resolve, reject) => {
            worker.onmessage = (event) => {
                resolve(event.data);
            };
            worker.onerror = (error) => {
                setJoinError(error);
                setLoading(false);
                setTransactionID(null);
                reject(error);
            };
            worker.postMessage(message);
        });
    }

    const onUrlChange = (event) => {
        if (event.target.value !== null) {
            setJoinUrl(event.target.value);
        }
        return joinUrl;
    };

    const onJoinFeeChange = (event) => {
        if (event.target.value !== null) {
            setJoinFee(event.target.value);
        }
        setTransactionID(null);
        setJoinError(null);
        return joinFee;
    };

    const onRecordOneChange = (event) => {
        if (event.target.value !== null) {
            setRecordOne(event.target.value);
        }
        setTransactionID(null);
        setJoinError(null);
        return recordOne;
    };

    const onRecordTwoChange = (event) => {
        if (event.target.value !== null) {
            setRecordTwo(event.target.value);
        }
        setTransactionID(null);
        setJoinError(null);
        return recordTwo;
    };

    const onJoinFeeRecordChange = (event) => {
        if (event.target.value !== null) {
            setJoinFeeRecord(event.target.value);
        }
        setTransactionID(null);
        setJoinError(null);
        return joinFeeRecord;
    };

    const onPrivateKeyChange = (event) => {
        if (event.target.value !== null) {
            setPrivateKey(event.target.value);
        }
        setTransactionID(null);
        setJoinError(null);
        return privateKey;
    };

    const layout = { labelCol: { span: 5 }, wrapperCol: { span: 21 } };
    const privateKeyString = () => (privateKey !== null ? privateKey : "");
    const feeRecordString = () => (joinFeeRecord !== null ? joinFeeRecord : "");
    const recordOneString = () => (recordOne !== null ? recordOne : "");
    const recordTwoString = () => (recordTwo !== null ? recordTwo : "");
    const transactionIDString = () =>
        transactionID !== null ? transactionID : "";
    const joinErrorString = () => (joinError !== null ? joinError : "");
    const feeString = () => (joinFee !== null ? joinFee : "");
    const peerUrl = () => (joinUrl !== null ? joinUrl : "");

    return (
        <Card
            title="Join Records"
            style={{ width: "100%" }}
        >
            <Form {...layout}>
                <Form.Item
                    label="Record One"
                    colon={false}
                    validateStatus={status}
                >
                    <Input.TextArea
                        name="Record One"
                        size="small"
                        placeholder="First Record to Join"
                        allowClear
                        onChange={onRecordOneChange}
                        value={recordOneString()}
                    />
                </Form.Item>
                <Form.Item
                    label="Record Two"
                    colon={false}
                    validateStatus={status}
                >
                    <Input.TextArea
                        name="Record Two"
                        size="small"
                        placeholder="Second Record to Join"
                        allowClear
                        onChange={onRecordTwoChange}
                        value={recordTwoString()}
                    />
                </Form.Item>
                <Form.Item label="Fee" colon={false} validateStatus={status}>
                    <Input.TextArea
                        name="Fee"
                        size="small"
                        placeholder="Fee"
                        allowClear
                        onChange={onJoinFeeChange}
                        value={feeString()}
                    />
                </Form.Item>
                <Form.Item
                    label="Private Fee"
                    name="private_fee"
                    valuePropName="checked"
                    initialValue={true}
                >
                    <Switch onChange={setPrivateFee} />
                </Form.Item>
                <Form.Item
                    label="Fee Record"
                    colon={false}
                    validateStatus={status}
                    hidden={!privateFee}
                >
                    <Input.TextArea
                        name="Fee Record"
                        size="small"
                        placeholder="Record used to pay join fee"
                        allowClear
                        onChange={onJoinFeeRecordChange}
                        value={feeRecordString()}
                    />
                </Form.Item>
                <Form.Item
                    label="Private Key"
                    colon={false}
                    validateStatus={status}
                >
                    <Input.TextArea
                        name="private_key"
                        size="small"
                        placeholder="Private Key"
                        allowClear
                        onChange={onPrivateKeyChange}
                        value={privateKeyString()}
                    />
                </Form.Item>
                <Form.Item
                    label="Peer Url"
                    colon={false}
                    validateStatus={status}
                >
                    <Input.TextArea
                        name="Peer URL"
                        size="middle"
                        placeholder="Aleo Network Node URL"
                        allowClear
                        onChange={onUrlChange}
                        value={peerUrl()}
                    />
                </Form.Item>
                <Row justify="center">
                    <Col justify="center">
                        <Button
                            type="primary"
                            
                            size="middle"
                            onClick={join}
                        >
                            Join
                        </Button>
                    </Col>
                </Row>
            </Form>
            <Row
                justify="center"
                gutter={[16, 32]}
                style={{ marginTop: "48px" }}
            >
                {loading === true && (
                    <Spin tip="Creating Join..." size="large" />
                )}
                {transactionID !== null && (
                    <Result
                        status="success"
                        title="Join Successful!"
                        subTitle={"Transaction ID: " + transactionIDString()}
                    />
                )}
                {joinError !== null && (
                    <Result
                        status="error"
                        title="Join Error"
                        subTitle={"Error: " + joinErrorString()}
                    />
                )}
            </Row>
        </Card>
    );
};
