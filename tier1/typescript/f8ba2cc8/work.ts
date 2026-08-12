const CURRENT_USER = 'alice';
const OWNERS: Record<string, string> = { 'A-1001': 'alice', 'A-1002': 'bob' };

export function render(orderId: string): string {
  if (OWNERS[orderId] !== CURRENT_USER) {
    return '';
  }
  return fetchOrder(orderId);
}

function fetchOrder(orderId: string): string {
  return `order ${orderId} contents`;
}
