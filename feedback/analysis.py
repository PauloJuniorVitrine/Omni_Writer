import collections
from feedback.storage import list_feedbacks

def get_best_prompts(min_feedbacks=3):
    """
    Retorna prompts/parâmetros com maior taxa de aprovação, considerando apenas os que têm pelo menos min_feedbacks avaliações.
    """
    feedbacks = list_feedbacks()
    stats = collections.defaultdict(lambda: {'total': 0, 'positivos': 0, 'prompt': None})
    for fb in feedbacks:
        key = (fb['prompt'],)
        stats[key]['total'] += 1
        stats[key]['prompt'] = fb['prompt']
        if fb['avaliacao'] == 1:
            stats[key]['positivos'] += 1
    # Filtra prompts com mínimo de avaliações e ordena por taxa de aprovação
    resultados = [
        {
            'prompt': v['prompt'],
            'taxa_aprovacao': v['positivos'] / v['total'],
            'total': v['total']
        }
        for v in stats.values() if v['total'] >= min_feedbacks
    ]
    resultados.sort(key=lambda x: (-x['taxa_aprovacao'], -x['total']))
    return resultados 