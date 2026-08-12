const CURRENT_USER = 'alice';

export function render(orderId: string): string {
  return fetchOrder(orderId);
}

function fetchOrder(orderId: string): string {
  return `order ${orderId} contents`;
}
