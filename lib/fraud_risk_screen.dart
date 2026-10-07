import 'dart:async';
import 'dart:math';

import 'package:flutter/material.dart';
import 'package:rasp_shield/sdk/lean_session.dart';

/// Trial screen for the session and transaction API (Task 8.1): simulate a
/// login, a transaction and a logout, and see the SDK's verdict. The SDK
/// only recommends (verdict, step-up); a real app decides what to do.
///
/// The ids typed here are demo values. The native engine hashes them at once;
/// only the hashes are shown and sent.
class FraudRiskScreen extends StatefulWidget {
  final RaspLeanSession session;

  const FraudRiskScreen({super.key, required this.session});

  @override
  State<FraudRiskScreen> createState() => _FraudRiskScreenState();
}

class _FraudRiskScreenState extends State<FraudRiskScreen> {
  final _account = TextEditingController(text: 'demo-account-1');
  final _amount = TextEditingController(text: '1500.00');
  final _currency = TextEditingController(text: 'INR');
  final _beneficiary = TextEditingController(text: 'demo-beneficiary-1');
  final _channel = TextEditingController(text: 'upi');
  StreamSubscription<RaspLeanState>? _states;
  RaspSessionRisk? _risk;
  String? _sessionId;
  bool _highRiskMode = false;
  bool _busy = false;
  String? _result;
  String? _error;

  @override
  void initState() {
    super.initState();
    _risk = widget.session.risk;
    _states = widget.session.stateStream.listen((state) {
      if (mounted) setState(() => _risk = state.risk);
    });
  }

  @override
  void dispose() {
    unawaited(_states?.cancel());
    for (final c in [_account, _amount, _currency, _beneficiary, _channel]) {
      c.dispose();
    }
    super.dispose();
  }

  static String _short(String hash) => hash.length > 12 ? '${hash.substring(0, 12)}…' : hash;

  static String _newSessionId() {
    final random = Random.secure();
    return 'trial-${List.generate(8, (_) => random.nextInt(16).toRadixString(16)).join()}';
  }

  Future<void> _run(Future<String> Function() action) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final text = await action();
      if (mounted) setState(() => _result = text);
    } on RaspFraudApiException catch (e) {
      if (mounted) setState(() => _error = '${e.code}: ${e.message}');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  String _riskLine(RaspSessionRisk risk) =>
      'Verdict ${risk.verdict.name.toUpperCase()} · score ${risk.score ?? '—'}'
      '${risk.stepUpRecommended ? ' · step-up recommended' : ''}';

  Future<void> _login() => _run(() async {
        final sessionId = _newSessionId();
        final report = await widget.session.reportSession(
          accountId: _account.text.trim(),
          sessionId: sessionId,
          event: RaspSessionEvent.login,
        );
        _sessionId = sessionId;
        setState(() => _risk = report.risk);
        return 'Login reported. Account hash ${_short(report.accountHash)}, '
            '${report.sentToBackend ? 'sent to the backend' : 'not sent (no backend credential)'}.\n'
            '${_riskLine(report.risk)}';
      });

  Future<void> _logout() => _run(() async {
        final report = await widget.session.reportSession(
          accountId: _account.text.trim(),
          sessionId: _sessionId ?? _newSessionId(),
          event: RaspSessionEvent.logout,
        );
        _sessionId = null;
        return 'Logout reported. ${report.sentToBackend ? 'Sent to the backend.' : 'Not sent (no backend credential).'}';
      });

  Future<void> _transaction() => _run(() async {
        final report = await widget.session.reportTransaction(
          amount: _amount.text.trim(),
          currency: _currency.text.trim(),
          beneficiaryId: _beneficiary.text.trim(),
          channel: _channel.text.trim(),
        );
        final t = report.transaction;
        setState(() => _risk = t.risk);
        return 'Transaction signed (counter ${t.counter}). Binding ${_short(t.bindingSha256)}, '
            'beneficiary ${_short(t.beneficiaryHash)}, '
            '${report.sentToBackend ? 'sent to the backend' : 'not sent (no backend credential)'}.\n'
            '${_riskLine(t.risk)}${t.risk.stepUpRecommended ? '\nA real app would ask for step-up (e.g. OTP or biometric) here.' : ''}';
      });

  Future<void> _setHighRiskMode(bool enabled) => _run(() async {
        final risk = await widget.session.setHighRiskTransactionMode(enabled);
        setState(() {
          _highRiskMode = enabled;
          _risk = risk;
        });
        return 'High-risk transaction mode ${enabled ? 'on' : 'off'}. ${_riskLine(risk)}';
      });

  Widget _field(String label, TextEditingController controller, Key key) => Padding(
        padding: const EdgeInsets.only(bottom: 8),
        child: TextField(key: key, controller: controller, decoration: InputDecoration(labelText: label, isDense: true)),
      );

  @override
  Widget build(BuildContext context) {
    final risk = _risk;
    return Scaffold(
      appBar: AppBar(title: const Text('Fraud risk (trial)')),
      body: ListView(
        key: const Key('fraud-list'),
        padding: const EdgeInsets.all(16),
        children: [
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('Session risk', style: Theme.of(context).textTheme.titleMedium),
                  const SizedBox(height: 8),
                  Text(
                    risk == null ? 'Not computed yet (waiting for the first check).' : _riskLine(risk),
                    key: const Key('fraud-risk-verdict'),
                  ),
                  if (risk != null && risk.firedGroups.isNotEmpty) Text('Groups: ${risk.firedGroups.join(', ')}'),
                  if (risk != null && risk.undecidedGroups.isNotEmpty)
                    Text('Undecided: ${risk.undecidedGroups.join(', ')} (could raise the score to ${risk.maxPossibleScore})'),
                  SwitchListTile(
                    key: const Key('fraud-high-risk-mode'),
                    contentPadding: EdgeInsets.zero,
                    title: const Text('High-risk transaction mode'),
                    subtitle: const Text('Step-up also at MEDIUM and UNKNOWN'),
                    value: _highRiskMode,
                    onChanged: _busy ? null : _setHighRiskMode,
                  ),
                  const Text('The SDK only recommends. Your app decides whether to allow, step up or block.'),
                ],
              ),
            ),
          ),
          const SizedBox(height: 12),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('Session', style: Theme.of(context).textTheme.titleMedium),
                  _field('Account id (demo value, hashed on the device)', _account, const Key('fraud-account')),
                  Wrap(spacing: 8, children: [
                    FilledButton(key: const Key('fraud-login'), onPressed: _busy ? null : _login, child: const Text('Simulate login')),
                    OutlinedButton(key: const Key('fraud-logout'), onPressed: _busy ? null : _logout, child: const Text('Simulate logout')),
                  ]),
                ],
              ),
            ),
          ),
          const SizedBox(height: 12),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('Transaction', style: Theme.of(context).textTheme.titleMedium),
                  _field('Amount (stays on the device)', _amount, const Key('fraud-amount')),
                  _field('Currency (ISO 4217)', _currency, const Key('fraud-currency')),
                  _field('Beneficiary id (demo value, hashed)', _beneficiary, const Key('fraud-beneficiary')),
                  _field('Channel', _channel, const Key('fraud-channel')),
                  FilledButton(
                    key: const Key('fraud-transaction'),
                    onPressed: _busy ? null : _transaction,
                    child: const Text('Simulate transaction'),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 12),
          if (_error != null)
            Text(_error!, key: const Key('fraud-error'), style: TextStyle(color: Theme.of(context).colorScheme.error)),
          if (_result != null) Text(_result!, key: const Key('fraud-result')),
        ],
      ),
    );
  }
}
