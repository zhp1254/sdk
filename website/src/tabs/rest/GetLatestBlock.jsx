import {useMemo, useState} from "react";
import { Button, Card, Col, Divider, Form, Input, Row } from "antd";
import axios from "axios";
import { CopyButton } from "../../components/CopyButton";

export const GetLatestBlock = () => {
    const [latestBlock, setLatestBlock] = useState(null);

    const tryRequest = () => {
        setLatestBlock(null);
        try {
            axios
                .get(`https://api.explorer.provable.com/v1/testnet/latest/block`)
                .then((response) =>
                    setLatestBlock(JSON.stringify(response.data, null, 2)),
                );
        } catch (error) {
            console.error(error);
        }
    };

    const layout = { labelCol: { span: 3 }, wrapperCol: { span: 21 } };

    const latestBlockString = useMemo(() => {
        return latestBlock !== null ? latestBlock.toString() : ""
    }, [latestBlock]);

    return (
        <Card
            title="Get Latest Block"
            style={{ width: "100%" }}
        >
            <Row justify="center">
                <Col>
                    <Button
                        type="primary"

                        size="middle"
                        onClick={tryRequest}
                    >
                        Get Latest Block
                    </Button>
                </Col>
            </Row>
            {latestBlock !== null ? (
                <Form {...layout}>
                    <Divider />
                    <Row align="middle">
                        <Col span={23}>
                            <Form.Item label="Block" colon={false}>
                                <Input.TextArea
                                    size="large"
                                    rows={15}
                                    placeholder="Block"
                                    value={latestBlockString}
                                    disabled
                                />
                            </Form.Item>
                        </Col>
                        <Col span={1} align="middle">
                            <CopyButton data={latestBlockString} />
                        </Col>
                    </Row>
                </Form>
            ) : null}
        </Card>
    );
};
