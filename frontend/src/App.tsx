import React, { Suspense, lazy, useState } from 'react';
import {
  FluentProvider,
  webLightTheme,
  webDarkTheme,
  Button,
  TabList,
  Tab,
  Text,
  Badge,
  Spinner,
  makeStyles,
  tokens,
  shorthands,
} from '@fluentui/react-components';
import {
  WeatherMoon20Regular,
  WeatherSunny20Regular,
  Pulse20Regular,
  Settings20Regular,
  Info20Regular,
} from '@fluentui/react-icons';
import { TracesView } from './components/TracesView';
const ConfigView = lazy(() =>
  import('./components/ConfigView').then((m) => ({ default: m.ConfigView }))
);

const useStyles = makeStyles({
  appContainer: {
    display: 'flex',
    flexDirection: 'column',
    height: '100vh',
    width: '100vw',
    backgroundColor: tokens.colorNeutralBackground2,
    overflow: 'hidden',
  },
  header: {
    height: '52px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    ...shorthands.padding('0px', '20px'),
    backgroundColor: tokens.colorNeutralBackground1,
    ...shorthands.borderBottom('1px', 'solid', tokens.colorNeutralStroke2),
    flexShrink: 0,
  },
  logoGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  },
  bodyLayout: {
    display: 'flex',
    flexGrow: 1,
    height: 'calc(100vh - 52px)',
    overflow: 'hidden',
  },
  sidebar: {
    width: '230px',
    backgroundColor: tokens.colorNeutralBackground1,
    ...shorthands.borderRight('1px', 'solid', tokens.colorNeutralStroke2),
    ...shorthands.padding('16px', '12px'),
    display: 'flex',
    flexDirection: 'column',
    flexShrink: 0,
  },
  mainContent: {
    flexGrow: 1,
    display: 'flex',
    flexDirection: 'column',
    height: '100%',
    overflow: 'hidden',
    backgroundColor: tokens.colorNeutralBackground2,
  },
  aboutCard: {
    ...shorthands.padding('30px'),
    maxWidth: '600px',
    lineHeight: '1.6',
  },
});

export const App: React.FC = () => {
  const styles = useStyles();
  const [isDarkMode, setIsDarkMode] = useState<boolean>(() => {
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  });
  const [currentNav, setCurrentNav] = useState<string>('traces');

  const theme = isDarkMode ? webDarkTheme : webLightTheme;

  return (
    <FluentProvider theme={theme} className={styles.appContainer}>
      <header className={styles.header}>
        <div className={styles.logoGroup}>
          <Text size={500} weight="bold" style={{ color: tokens.colorBrandForeground1 }}>
            vproxy
          </Text>
          <Badge appearance="tint" color="brand">
            v1.0.8
          </Badge>
          <Badge appearance="filled" color="success">
            eBPF / TUN Active
          </Badge>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Button
            appearance="subtle"
            icon={isDarkMode ? <WeatherSunny20Regular /> : <WeatherMoon20Regular />}
            onClick={() => setIsDarkMode(!isDarkMode)}
            aria-label="Toggle theme"
          >
            {isDarkMode ? 'Light Mode' : 'Dark Mode'}
          </Button>
        </div>
      </header>

      <div className={styles.bodyLayout}>
        <aside className={styles.sidebar}>
          <TabList
            vertical
            selectedValue={currentNav}
            onTabSelect={(_, data) => setCurrentNav(data.value as string)}
          >
            <Tab value="traces" icon={<Pulse20Regular />}>
              HTTP Traces
            </Tab>
            <Tab value="config" icon={<Settings20Regular />}>
              Rules & Config
            </Tab>
            <Tab value="about" icon={<Info20Regular />}>
              System Status
            </Tab>
          </TabList>
        </aside>

        <main className={styles.mainContent}>
          {currentNav === 'traces' && <TracesView />}
          {currentNav === 'config' && (
            <Suspense fallback={<Spinner style={{ marginTop: 60 }} label="Loading editor..." />}>
              <ConfigView isDarkMode={isDarkMode} />
            </Suspense>
          )}
          {currentNav === 'about' && (
            <div className={styles.aboutCard}>
              <Text size={600} weight="semibold" block style={{ marginBottom: '16px' }}>
                vproxy System Status
              </Text>
              <Text block style={{ marginBottom: '8px' }}>
                <b>Core Engine:</b> eBPF cgroup redirection & Wintun transparent proxy
              </Text>
              <Text block style={{ marginBottom: '8px' }}>
                <b>L7 MITM Engine:</b> Dynamic Root CA generation and HTTPS TLS termination
              </Text>
              <Text block style={{ marginBottom: '8px' }}>
                <b>L7 Rewrite:</b> Whistle-style regex path rewriting and local file mock
              </Text>
              <Text block style={{ marginBottom: '8px' }}>
                <b>OpenTelemetry:</b> Distributed tracing with kernel/process metadata
              </Text>
              <Text block style={{ marginBottom: '16px', color: tokens.colorNeutralForeground3 }}>
                Dashboard rebuilt with Microsoft Fluent UI v9, React, and TypeScript.
              </Text>
            </div>
          )}
        </main>
      </div>
    </FluentProvider>
  );
};
