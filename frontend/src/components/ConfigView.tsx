import React, { useState, useEffect } from 'react';
import {
  Button,
  Input,
  TabList,
  Tab,
  Card,
  CardHeader,
  Text,
  Badge,
  MessageBar,
  MessageBarTitle,
  MessageBarBody,
  Spinner,
  Dropdown,
  Option,
  Switch,
  makeStyles,
  tokens,
  shorthands,
} from '@fluentui/react-components';
import {
  Save20Regular,
  Add20Regular,
  Delete20Regular,
  ArrowSync20Regular,
} from '@fluentui/react-icons';
import Editor from '@monaco-editor/react';
import '../monaco-setup';
import { VProxyConfig } from '../types';
import { fetchConfig, saveConfig } from '../api';
import { parseRuleItem, toggleRuleActive } from '../utils/rules';

export interface ConfigViewProps {
  isDarkMode?: boolean;
}

const useStyles = makeStyles({
  container: {
    display: 'flex',
    flexDirection: 'column',
    height: '100%',
    ...shorthands.padding('20px'),
    boxSizing: 'border-box',
    overflow: 'hidden',
  },
  scrollableTabContent: {
    flexGrow: 1,
    overflowY: 'auto',
    paddingRight: '6px',
    minHeight: 0,
  },
  rawTabContent: {
    display: 'flex',
    flexDirection: 'column',
    flexGrow: 1,
    minHeight: 0,
    height: '100%',
  },
  card: {
    backgroundColor: tokens.colorNeutralBackground1,
    ...shorthands.padding('16px'),
    marginBottom: '20px',
  },
  rowItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    ...shorthands.padding('8px', '12px'),
    ...shorthands.borderRadius(tokens.borderRadiusSmall),
    backgroundColor: tokens.colorNeutralBackground2,
    marginBottom: '8px',
  },
  editorWrapper: {
    flexGrow: 1,
    minHeight: 0,
    width: '100%',
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    ...shorthands.border('1px', 'solid', tokens.colorNeutralStroke1),
    overflow: 'hidden',
  },
  sectionTitle: {
    fontWeight: '600',
    fontSize: '16px',
    marginBottom: '12px',
  },
});

export const ConfigView: React.FC<ConfigViewProps> = ({ isDarkMode = false }) => {
  const styles = useStyles();
  const [activeTab, setActiveTab] = useState<string>('rules');
  const [config, setConfig] = useState<VProxyConfig | null>(null);
  const [rawJson, setRawJson] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // New rule form states
  const [newRulePattern, setNewRulePattern] = useState<string>('');
  const [newRuleType, setNewRuleType] = useState<string>('DOMAIN');
  const [newRuleAction, setNewRuleAction] = useState<string>('PROXY');

  // New rewrite rule form states
  const [newRewritePattern, setNewRewritePattern] = useState<string>('');
  const [newRewriteTarget, setNewRewriteTarget] = useState<string>('');

  const loadData = async () => {
    setLoading(true);
    try {
      const cfg = await fetchConfig();
      setConfig(cfg);
      setRawJson(JSON.stringify(cfg, null, 2));
      setMessage(null);
    } catch (err) {
      setMessage({
        type: 'error',
        text: `Failed to load config: ${err instanceof Error ? err.message : String(err)}`,
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleSaveJson = async () => {
    try {
      const parsed: VProxyConfig = JSON.parse(rawJson);
      setSaving(true);
      await saveConfig(parsed);
      setConfig(parsed);
      setMessage({ type: 'success', text: 'Configuration saved and hot-reloaded successfully!' });
    } catch (err) {
      setMessage({
        type: 'error',
        text: `Invalid JSON or save failed: ${err instanceof Error ? err.message : String(err)}`,
      });
    } finally {
      setSaving(false);
    }
  };

  const handleSaveConfig = async (updated: VProxyConfig) => {
    setSaving(true);
    try {
      await saveConfig(updated);
      setConfig(updated);
      setRawJson(JSON.stringify(updated, null, 2));
      setMessage({ type: 'success', text: 'Rule updated and hot-reloaded successfully!' });
    } catch (err) {
      setMessage({
        type: 'error',
        text: `Failed to update rule: ${err instanceof Error ? err.message : String(err)}`,
      });
    } finally {
      setSaving(false);
    }
  };

  const handleAddRule = () => {
    if (!config || !newRulePattern.trim()) return;
    const ruleStr = `${newRuleType},${newRulePattern.trim()},${newRuleAction}`;
    const updated: VProxyConfig = {
      ...config,
      rules: [ruleStr, ...config.rules],
    };
    setNewRulePattern('');
    handleSaveConfig(updated);
  };

  const handleDeleteRule = (index: number) => {
    if (!config) return;
    const updated: VProxyConfig = {
      ...config,
      rules: config.rules.filter((_, i) => i !== index),
    };
    handleSaveConfig(updated);
  };

  const handleToggleRule = (index: number) => {
    if (!config || !config.rules) return;
    const updatedRules = [...config.rules];
    updatedRules[index] = toggleRuleActive(updatedRules[index]);
    const updated: VProxyConfig = {
      ...config,
      rules: updatedRules,
    };
    handleSaveConfig(updated);
  };

  const handleAddRewrite = () => {
    if (!config || !newRewritePattern.trim() || !newRewriteTarget.trim()) return;
    const rewriteStr = `${newRewritePattern.trim()} ${newRewriteTarget.trim()}`;
    const updated: VProxyConfig = {
      ...config,
      rewrites: [rewriteStr, ...(config.rewrites || [])],
    };
    setNewRewritePattern('');
    setNewRewriteTarget('');
    handleSaveConfig(updated);
  };

  const handleDeleteRewrite = (index: number) => {
    if (!config || !config.rewrites) return;
    const updated: VProxyConfig = {
      ...config,
      rewrites: config.rewrites.filter((_, i) => i !== index),
    };
    handleSaveConfig(updated);
  };

  const getActionBadgeColor = (action: string): 'brand' | 'success' | 'warning' | 'danger' | 'informative' => {
    switch (action.toUpperCase()) {
      case 'PROXY':
        return 'brand';
      case 'DIRECT':
        return 'informative';
      case 'INTERCEPT':
        return 'warning';
      case 'BLOCK':
        return 'danger';
      default:
        return 'informative';
    }
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', padding: '60px' }}>
        <Spinner label="Loading configuration..." />
      </div>
    );
  }

  return (
    <div className={styles.container}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
        <TabList
          selectedValue={activeTab}
          onTabSelect={(_, data) => {
            const nextTab = data.value as string;
            if (nextTab === 'raw' && config) {
              setRawJson(JSON.stringify(config, null, 2));
            }
            setActiveTab(nextTab);
          }}
        >
          <Tab value="rules">Rules & Routing</Tab>
          <Tab value="rewrites">L7 Rewrites & Mock</Tab>
          <Tab value="raw">Raw JSON Editor</Tab>
        </TabList>

        <Button icon={<ArrowSync20Regular />} onClick={loadData}>
          Reload
        </Button>
      </div>

      {message && (
        <MessageBar intent={message.type} style={{ marginBottom: '16px' }}>
          <MessageBarBody>
            <MessageBarTitle>{message.type === 'success' ? 'Success' : 'Error'}</MessageBarTitle>
            {message.text}
          </MessageBarBody>
        </MessageBar>
      )}

      {activeTab === 'rules' && config && (
        <div className={styles.scrollableTabContent}>
          <Card className={styles.card}>
            <CardHeader header={<Text weight="semibold">Add Routing Rule</Text>} />
            <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
              <Dropdown
                style={{ minWidth: '130px' }}
                value={newRuleType}
                selectedOptions={[newRuleType]}
                onOptionSelect={(_, data) => setNewRuleType(data.optionValue || 'DOMAIN')}
              >
                <Option value="DOMAIN">DOMAIN</Option>
                <Option value="PROCESS">PROCESS</Option>
                <Option value="IP_CIDR">IP_CIDR</Option>
              </Dropdown>

              <Input
                style={{ flexGrow: 1, minWidth: '220px' }}
                placeholder="Pattern (e.g. google.com or curl.exe or 10.0.0.0/8)"
                value={newRulePattern}
                onChange={(_, data) => setNewRulePattern(data.value)}
              />

              <Dropdown
                style={{ minWidth: '130px' }}
                value={newRuleAction}
                selectedOptions={[newRuleAction]}
                onOptionSelect={(_, data) => setNewRuleAction(data.optionValue || 'PROXY')}
              >
                <Option value="PROXY">PROXY</Option>
                <Option value="DIRECT">DIRECT</Option>
                <Option value="INTERCEPT">INTERCEPT</Option>
                <Option value="BLOCK">BLOCK</Option>
              </Dropdown>

              <Button appearance="primary" icon={<Add20Regular />} onClick={handleAddRule} disabled={saving}>
                Add Rule
              </Button>
            </div>
          </Card>

          {(() => {
            const rules = config.rules || [];
            const parsedRules = rules.map((r) => parseRuleItem(r));
            const activeCount = parsedRules.filter((r) => r.isActive).length;
            const inactiveCount = parsedRules.length - activeCount;

            return (
              <>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
                  <Text weight="semibold" size={400}>Rules ({rules.length})</Text>
                  <Badge appearance="filled" color="brand">{activeCount} Active</Badge>
                  {inactiveCount > 0 && <Badge appearance="tint" color="subtle">{inactiveCount} Inactive</Badge>}
                </div>

                {rules.map((_, idx) => {
                  const parsed = parsedRules[idx];
                  return (
                    <div
                      key={idx}
                      className={styles.rowItem}
                      style={{
                        opacity: parsed.isActive ? 1 : 0.55,
                        filter: parsed.isActive ? 'none' : 'grayscale(0.4)',
                        transition: 'opacity 0.2s ease',
                      }}
                    >
                      <Switch
                        checked={parsed.isActive}
                        onChange={() => handleToggleRule(idx)}
                        disabled={saving}
                        aria-label="Toggle rule active state"
                      />
                      {!parsed.isActive && (
                        <Badge appearance="tint" color="subtle">
                          INACTIVE
                        </Badge>
                      )}
                      {parsed.type && <Badge appearance="outline">{parsed.type}</Badge>}
                      <Text
                        style={{
                          fontFamily: 'monospace',
                          flexGrow: 1,
                          textDecoration: parsed.isActive ? 'none' : 'line-through',
                          color: parsed.isActive ? tokens.colorNeutralForeground1 : tokens.colorNeutralForeground3,
                        }}
                      >
                        {parsed.pattern}
                      </Text>
                      {parsed.action && (
                        <Badge
                          appearance={parsed.isActive ? 'filled' : 'outline'}
                          color={parsed.isActive ? getActionBadgeColor(parsed.action) : 'subtle'}
                        >
                          {parsed.action}
                        </Badge>
                      )}
                      <Button
                        appearance="subtle"
                        icon={<Delete20Regular />}
                        onClick={() => handleDeleteRule(idx)}
                        disabled={saving}
                      />
                    </div>
                  );
                })}
              </>
            );
          })()}
        </div>
      )}

      {activeTab === 'rewrites' && config && (
        <div className={styles.scrollableTabContent}>
          <Card className={styles.card}>
            <CardHeader header={<Text weight="semibold">Add L7 Rewrite / Mock Rule</Text>} />
            <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
              <Input
                style={{ flex: 1, minWidth: '260px' }}
                placeholder="Source URL / Pattern (e.g. https://api.com/v1/*)"
                value={newRewritePattern}
                onChange={(_, data) => setNewRewritePattern(data.value)}
              />
              <Input
                style={{ flex: 1, minWidth: '260px' }}
                placeholder="Target URL or file:// (e.g. file:///tmp/mock.json)"
                value={newRewriteTarget}
                onChange={(_, data) => setNewRewriteTarget(data.value)}
              />
              <Button appearance="primary" icon={<Add20Regular />} onClick={handleAddRewrite} disabled={saving}>
                Add Rewrite
              </Button>
            </div>
          </Card>

          <div className={styles.sectionTitle}>Active Rewrites ({config.rewrites?.length || 0})</div>
          {(!config.rewrites || config.rewrites.length === 0) ? (
            <Text italic style={{ color: tokens.colorNeutralForeground3 }}>
              No rewrite or mock rules active
            </Text>
          ) : (
            config.rewrites.map((rw, idx) => (
              <div key={idx} className={styles.rowItem}>
                <Badge appearance="filled" color={rw.includes('file://') ? 'warning' : 'brand'}>
                  {rw.includes('file://') ? 'MOCK' : 'REWRITE'}
                </Badge>
                <Text style={{ fontFamily: 'monospace', flexGrow: 1 }}>{rw}</Text>
                <Button
                  appearance="subtle"
                  icon={<Delete20Regular />}
                  onClick={() => handleDeleteRewrite(idx)}
                  disabled={saving}
                />
              </div>
            ))
          )}
        </div>
      )}

      {activeTab === 'raw' && (
        <div className={styles.rawTabContent}>
          <div className={styles.editorWrapper}>
            <Editor
              height="100%"
              defaultLanguage="json"
              language="json"
              value={rawJson}
              theme={isDarkMode ? 'vs-dark' : 'light'}
              onChange={(val) => setRawJson(val ?? '')}
              options={{
                minimap: { enabled: true },
                fontSize: 13,
                lineNumbers: 'on',
                folding: true,
                scrollBeyondLastLine: false,
                automaticLayout: true,
                tabSize: 2,
                formatOnPaste: true,
              }}
            />
          </div>
          <div style={{ marginTop: '12px', flexShrink: 0 }}>
            <Button
              appearance="primary"
              icon={<Save20Regular />}
              onClick={handleSaveJson}
              disabled={saving}
            >
              {saving ? 'Saving...' : 'Save & Hot Reload Config'}
            </Button>
          </div>
        </div>
      )}
    </div>
  );
};
