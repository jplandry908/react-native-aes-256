import * as React from 'react';

import { StyleSheet, View, Text } from 'react-native';
import {
  encrypt,
  decrypt,
  generateSecureKey,
  generateSecureIV,
} from 'react-native-aes-256';

export default function App() {
  const [result, setResult] = React.useState<string | undefined>();

  React.useEffect(() => {
    run();
  }, []);

  const run = async () => {
    try {
      const secureKey = await generateSecureKey('your password1');
      const secureIV = await generateSecureIV('your password');
      const data = 'test1';
      console.log({
        secureIV,
        secureKey,
      });
      const encryptedData = await encrypt(secureKey, secureIV, data);
      console.log('---encryptedData--', encryptedData);
      const decryptedData = await decrypt(secureKey, secureIV, encryptedData);
      setResult(decryptedData);
    } catch (e) {
      console.log('---e', e);
    }
  };

  return (
    <View style={styles.container}>
      <Text>Result: {result}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  box: {
    width: 60,
    height: 60,
    marginVertical: 20,
  },
});
