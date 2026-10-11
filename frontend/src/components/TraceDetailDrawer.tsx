import React, { useState } from 'react';
import {
  OverlayDrawer,
  DrawerHeader,
  DrawerHeaderTitle,
  DrawerBody,
  Button,
  TabList,
  Tab,
  Badge,
  Text,
  makeStyles,
  tokens,
  shorthands,
  Tooltip,
} from '@fluentui/react-components';
import {
  Dismiss24Regular,
  Copy20Regular,
  Checkmark20Regular,
  Clock20Regular,
} from '@fluentui/react-icons';
import { TraceEntry } from '../types';
import { generateCurlCommand } from '../utils/curl';

const useStyles = makeStyles({
  badgeMethod: {
    fontFamily: 'monospace',
    fontWeight: 'bold',
  },
  headerInfo: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    marginTop: '6px',
    flexWrap: 'wrap',
  },
  urlText: {
    wordBreak: 'break-all',
    fontFamily: 'monospace',
    fontSize: '13px',
    color: tokens.colorNeutralForeground2,
    marginTop: '6px',
  },
  codeBox: {
    backgroundColor: tokens.colorNeutralBackground2,
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke2),
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    ...shorthands.padding('12px'),
    fontFamily: 'Consolas, Monaco, "Courier New", monospace',
    fontSize: '12px',
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-all',
    overflowX: 'auto',
    maxHeight: '400px',
  },
  headerTable: {
    width: '100%',
    borderCollapse: 'collapse',
    fontSize: '12px',
    '& tr': {
      ...shorthands.borderBottom('1px', 'solid', tokens.colorNeutralStroke3),
    },
    '& th, & td': {
      ...shorthands.padding('8px', '6px'),
      textAlign: 'left',
      verticalAlign: 'top',
    },
    '& th': {
      color: tokens.colorNeutralForeground3,
      width: '35%',
      fontFamily: 'monospace',
      fontWeight: '600',
    },
    '& td': {
      fontFamily: 'monospace',
      wordBreak: 'break-all',
    },
  },
  sectionTitle: {
    fontWeight: '600',
    fontSize: '14px',
    marginBottom: '8px',
    marginTop: '16px',
  },
});

interface TraceDetailDrawerProps {
  trace: TraceEntry | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export const TraceDetailDrawer: React.FC<TraceDetailDrawerProps> = ({
  trace,
  open,
  onOpenChange,
}) => {
  const styles = useStyles();
  const [selectedTab, setSelectedTab] = useState<string>('headers');
  const [copied, setCopied] = useState<boolean>(false);

  if (!trace) return null;

  const handleCopyCurl = async () => {
    const curl = generateCurlCommand(trace);
    try {
      await navigator.clipboard.writeText(curl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (e) {
      console.error('Failed to copy cURL', e);
    }
  };

  const renderJsonOrRaw = (content?: string) => {
    if (!content) return <Text italic>Empty body</Text>;
    try {
      const parsed = JSON.parse(content);
      return <pre className={styles.codeBox}>{JSON.stringify(parsed, null, 2)}</pre>;
    } catch {
      return <pre className={styles.codeBox}>{content}</pre>;
    }
  };

  const statusColor = trace.status_code >= 400 ? 'danger' : 'success';

  return (
    <OverlayDrawer
      open={open}
      position="end"
      size="large"
      onOpenChange={(_, state) => onOpenChange(state.open)}
    >
      <DrawerHeader>
        <DrawerHeaderTitle
          action={
            <Button
              appearance="subtle"
              aria-label="Close"
              icon={<Dismiss24Regular />}
              onClick={() => onOpenChange(false)}
            />
          }
        >
          <div className={styles.headerInfo}>
            <Badge appearance="filled" color="informative" className={styles.badgeMethod}>
              {trace.method}
            </Badge>
            <Badge appearance="filled" color={statusColor}>
              {trace.status_code}
            </Badge>
            <Text size={200} style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
              <Clock20Regular style={{ fontSize: '14px' }} />
              {trace.latency_ms.toFixed(1)}ms
            </Text>
            <Tooltip content={copied ? 'Copied!' : 'Copy as cURL'} relationship="label">
              <Button
                appearance="outline"
                size="small"
                icon={copied ? <Checkmark20Regular /> : <Copy20Regular />}
                onClick={handleCopyCurl}
              >
                {copied ? 'Copied' : 'Copy cURL'}
              </Button>
            </Tooltip>
          </div>
          <div className={styles.urlText}>{trace.url}</div>
        </DrawerHeaderTitle>
      </DrawerHeader>

      <DrawerBody>
        <TabList
          selectedValue={selectedTab}
          onTabSelect={(_, data) => setSelectedTab(data.value as string)}
          style={{ marginBottom: '16px' }}
        >
          <Tab value="headers">Headers</Tab>
          <Tab value="req_body">Request Body</Tab>
          <Tab value="resp_body">Response Body</Tab>
          <Tab value="curl">cURL Replay</Tab>
        </TabList>

        {selectedTab === 'headers' && (
          <div>
            <div className={styles.sectionTitle}>Request Headers</div>
            {trace.req_headers && Object.keys(trace.req_headers).length > 0 ? (
              <table className={styles.headerTable}>
                <tbody>
                  {Object.entries(trace.req_headers).map(([k, values]) => (
                    <tr key={k}>
                      <th>{k}</th>
                      <td>{values.join(', ')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <Text italic>No request headers</Text>
            )}

            <div className={styles.sectionTitle}>Response Headers</div>
            {trace.resp_headers && Object.keys(trace.resp_headers).length > 0 ? (
              <table className={styles.headerTable}>
                <tbody>
                  {Object.entries(trace.resp_headers).map(([k, values]) => (
                    <tr key={k}>
                      <th>{k}</th>
                      <td>{values.join(', ')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <Text italic>No response headers</Text>
            )}
          </div>
        )}

        {selectedTab === 'req_body' && (
          <div>
            <div className={styles.sectionTitle}>Request Payload</div>
            {renderJsonOrRaw(trace.req_body)}
          </div>
        )}

        {selectedTab === 'resp_body' && (
          <div>
            <div className={styles.sectionTitle}>Response Payload</div>
            {renderJsonOrRaw(trace.resp_body)}
          </div>
        )}

        {selectedTab === 'curl' && (
          <div>
            <div className={styles.sectionTitle}>Generated cURL Replay Command</div>
            <pre className={styles.codeBox}>{generateCurlCommand(trace)}</pre>
            <Button
              appearance="primary"
              icon={copied ? <Checkmark20Regular /> : <Copy20Regular />}
              onClick={handleCopyCurl}
              style={{ marginTop: '12px' }}
            >
              {copied ? 'Copied to Clipboard' : 'Copy cURL Command'}
            </Button>
          </div>
        )}
      </DrawerBody>
    </OverlayDrawer>
  );
};
