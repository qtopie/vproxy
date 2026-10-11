import React, { useState, useEffect, useMemo } from 'react';
import {
  Table,
  TableHeader,
  TableRow,
  TableHeaderCell,
  TableBody,
  TableCell,
  TableCellLayout,
  Button,
  Input,
  Dropdown,
  Option,
  Badge,
  Text,
  Spinner,
  makeStyles,
  tokens,
  shorthands,
} from '@fluentui/react-components';
import {
  ArrowSync20Regular,
  Search20Regular,
  Delete20Regular,
} from '@fluentui/react-icons';
import { TraceEntry } from '../types';
import { fetchTraces } from '../api';
import { TraceDetailDrawer } from './TraceDetailDrawer';

const useStyles = makeStyles({
  container: {
    display: 'flex',
    flexDirection: 'column',
    height: '100%',
    ...shorthands.padding('20px'),
    boxSizing: 'border-box',
    overflow: 'hidden',
  },
  toolbar: {
    display: 'flex',
    gap: '12px',
    alignItems: 'center',
    marginBottom: '16px',
    flexWrap: 'wrap',
  },
  searchBox: {
    minWidth: '280px',
    flexGrow: 1,
  },
  tableContainer: {
    flexGrow: 1,
    overflowY: 'auto',
    backgroundColor: tokens.colorNeutralBackground1,
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke2),
  },
  tableRow: {
    cursor: 'pointer',
    '&:hover': {
      backgroundColor: tokens.colorNeutralBackground1Hover,
    },
  },
  methodBadge: {
    fontFamily: 'monospace',
    fontWeight: 'bold',
    minWidth: '55px',
    textAlign: 'center',
  },
  statusBadge: {
    fontFamily: 'monospace',
    fontWeight: 'bold',
  },
  codeCell: {
    fontFamily: 'Consolas, Monaco, monospace',
    fontSize: '13px',
  },
});

export const TracesView: React.FC = () => {
  const styles = useStyles();
  const [traces, setTraces] = useState<TraceEntry[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [refreshInterval, setRefreshInterval] = useState<number>(3000); // 3s default
  const [selectedTrace, setSelectedTrace] = useState<TraceEntry | null>(null);
  const [drawerOpen, setDrawerOpen] = useState<boolean>(false);

  const loadData = async (showLoading = false) => {
    if (showLoading) setLoading(true);
    try {
      const data = await fetchTraces();
      setTraces(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      if (showLoading) setLoading(false);
    }
  };

  useEffect(() => {
    loadData(true);
  }, []);

  useEffect(() => {
    if (refreshInterval <= 0) return;
    const interval = setInterval(() => {
      loadData(false);
    }, refreshInterval);
    return () => clearInterval(interval);
  }, [refreshInterval]);

  const filteredTraces = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    return traces
      .slice()
      .reverse()
      .filter((t) => {
        // Status filter
        if (statusFilter === '2xx' && (t.status_code < 200 || t.status_code >= 300)) return false;
        if (statusFilter === '3xx' && (t.status_code < 300 || t.status_code >= 400)) return false;
        if (statusFilter === '4xx' && (t.status_code < 400 || t.status_code >= 500)) return false;
        if (statusFilter === '5xx' && t.status_code < 500) return false;

        // Search query
        if (!query) return true;
        return (
          t.url.toLowerCase().includes(query) ||
          t.host.toLowerCase().includes(query) ||
          t.path.toLowerCase().includes(query) ||
          t.method.toLowerCase().includes(query) ||
          t.status_code.toString().includes(query)
        );
      });
  }, [traces, searchQuery, statusFilter]);

  const handleRowClick = (trace: TraceEntry) => {
    setSelectedTrace(trace);
    setDrawerOpen(true);
  };

  const getMethodColor = (method: string): 'informative' | 'brand' | 'success' | 'warning' | 'danger' => {
    switch (method.toUpperCase()) {
      case 'GET':
        return 'informative';
      case 'POST':
        return 'success';
      case 'PUT':
      case 'PATCH':
        return 'warning';
      case 'DELETE':
        return 'danger';
      default:
        return 'brand';
    }
  };

  const getStatusColor = (status: number): 'success' | 'warning' | 'danger' => {
    if (status >= 200 && status < 300) return 'success';
    if (status >= 300 && status < 400) return 'warning';
    return 'danger';
  };

  return (
    <div className={styles.container}>
      <div className={styles.toolbar}>
        <Input
          className={styles.searchBox}
          placeholder="Filter by host, path, method, status..."
          contentBefore={<Search20Regular />}
          value={searchQuery}
          onChange={(_, data) => setSearchQuery(data.value)}
        />

        <Dropdown
          style={{ minWidth: '110px' }}
          value={statusFilter === 'all' ? 'All Status' : statusFilter.toUpperCase()}
          selectedOptions={[statusFilter]}
          onOptionSelect={(_, data) => setStatusFilter(data.optionValue || 'all')}
        >
          <Option value="all">All Status</Option>
          <Option value="2xx">2xx OK</Option>
          <Option value="3xx">3xx Redir</Option>
          <Option value="4xx">4xx Error</Option>
          <Option value="5xx">5xx Error</Option>
        </Dropdown>

        <Dropdown
          style={{ minWidth: '130px' }}
          value={
            refreshInterval === 0
              ? 'Auto: Off'
              : `Auto: ${refreshInterval / 1000}s`
          }
          selectedOptions={[String(refreshInterval)]}
          onOptionSelect={(_, data) => setRefreshInterval(Number(data.optionValue))}
        >
          <Option value="0">Auto: Off</Option>
          <Option value="1000">Auto: 1s</Option>
          <Option value="3000">Auto: 3s</Option>
          <Option value="5000">Auto: 5s</Option>
        </Dropdown>

        <Button icon={<ArrowSync20Regular />} onClick={() => loadData(true)}>
          Refresh
        </Button>

        <Button
          icon={<Delete20Regular />}
          appearance="subtle"
          onClick={() => setTraces([])}
        >
          Clear View
        </Button>

        <Text size={200} style={{ marginLeft: 'auto', color: tokens.colorNeutralForeground3 }}>
          {filteredTraces.length} / {traces.length} requests
        </Text>
      </div>

      {loading && traces.length === 0 ? (
        <div style={{ display: 'flex', justifyContent: 'center', padding: '40px' }}>
          <Spinner label="Loading deep traces..." />
        </div>
      ) : error ? (
        <div style={{ color: tokens.colorPaletteRedForeground1, padding: '20px' }}>
          Failed to load traces: {error}
        </div>
      ) : (
        <div className={styles.tableContainer}>
          <Table aria-label="HTTP Traces Table" noNativeElements={false}>
            <TableHeader>
              <TableRow>
                <TableHeaderCell style={{ width: '80px' }}>Method</TableHeaderCell>
                <TableHeaderCell style={{ width: '180px' }}>Host</TableHeaderCell>
                <TableHeaderCell style={{ flex: 1 }}>Path</TableHeaderCell>
                <TableHeaderCell style={{ width: '90px' }}>Status</TableHeaderCell>
                <TableHeaderCell style={{ width: '100px' }}>Latency</TableHeaderCell>
                <TableHeaderCell style={{ width: '120px' }}>Time</TableHeaderCell>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredTraces.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} style={{ textAlign: 'center', padding: '40px' }}>
                    <Text italic color="neutralForeground3">
                      No matching traces found
                    </Text>
                  </TableCell>
                </TableRow>
              ) : (
                filteredTraces.map((t) => (
                  <TableRow
                    key={t.id}
                    className={styles.tableRow}
                    onClick={() => handleRowClick(t)}
                  >
                    <TableCell>
                      <Badge
                        appearance="filled"
                        color={getMethodColor(t.method)}
                        className={styles.methodBadge}
                      >
                        {t.method}
                      </Badge>
                    </TableCell>
                    <TableCell className={styles.codeCell}>{t.host}</TableCell>
                    <TableCell className={styles.codeCell}>
                      <TableCellLayout truncate>{t.path}</TableCellLayout>
                    </TableCell>
                    <TableCell>
                      <Badge
                        appearance="tint"
                        color={getStatusColor(t.status_code)}
                        className={styles.statusBadge}
                      >
                        {t.status_code}
                      </Badge>
                    </TableCell>
                    <TableCell className={styles.codeCell}>
                      {t.latency_ms.toFixed(1)}ms
                    </TableCell>
                    <TableCell style={{ fontSize: '12px', color: tokens.colorNeutralForeground3 }}>
                      {new Date(t.timestamp).toLocaleTimeString()}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      )}

      <TraceDetailDrawer
        trace={selectedTrace}
        open={drawerOpen}
        onOpenChange={setDrawerOpen}
      />
    </div>
  );
};
